// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Multi-OS lexical and symlink-aware path canonicaliser (`D-10`).

use std::borrow::Cow;
use std::fmt;

use grdr_model::DataClass;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;

use crate::analyze::decode::decode_url_percent_once_bytes;
use crate::analyze::path_rules::{
    contains_windows_short_name, has_unresolved_parent_escape, is_tilde_user_path,
    is_windows_drive_head, is_windows_drive_relative, path_within_workspace,
};
use crate::analyze::types::{
    MalformedKind, MalformedReason, Resolution, Span, UnresolvedKind, UnresolvedReason,
};

pub use crate::analyze::path_rules::{
    ProtectedPathClass, VolumeCase, classify_protected_path, split_ntfs_ads,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsKind {
    Linux,
    MacOs,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SymlinkResolution {
    Direct,
    Pending,
    ResolvedSymlink { realpath: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathFacts {
    pub os: OsKind,
    pub volume_case: VolumeCase,
    pub symlink: SymlinkResolution,
    pub workspace_root: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalPath {
    pub canonical: String,
    pub base_without_ads: String,
    pub ads_stream: Option<String>,
    pub escaped_workspace: bool,
    pub classes: Vec<ProtectedPathClass>,
}

impl fmt::Debug for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalPath")
            .field("canonical_len", &self.canonical.len())
            .field("ads_present", &self.ads_stream.is_some())
            .field("escaped_workspace", &self.escaped_workspace)
            .field("classes", &self.classes)
            .finish()
    }
}

impl CanonicalPath {
    #[must_use]
    pub const fn data_class() -> DataClass {
        DataClass::Content
    }
}

/// Lexical path canonicalisation preserving idempotency across `file://`, Windows, and POSIX paths.
#[must_use]
pub fn canonicalize_path_lex(raw: &str) -> String {
    let non_nul = raw.split('\0').next().unwrap_or("");
    canonicalize_clean_lex(non_nul, false)
}

#[must_use]
pub(crate) fn canonicalize_windows_path_lex(raw: &str) -> String {
    let non_nul = raw.split('\0').next().unwrap_or("");
    canonicalize_clean_lex(non_nul, true)
}

/// Resolves a path lexically and against `PathFacts`, failing closed on control bytes, 8.3 names, and unresolved roots.
#[must_use]
pub fn resolve_path(raw: &str, facts: Option<&PathFacts>) -> Resolution<CanonicalPath> {
    let lex_prepared = match prepare_checked_path(raw) {
        Ok(prepared) => prepared,
        Err(reason) => return Resolution::Malformed(reason),
    };
    let is_windows = facts.is_some_and(|f| f.os == OsKind::Windows);
    let lex = canonicalize_clean_lex(&lex_prepared, is_windows);
    let mut effective = lex.clone();
    let mut resolved_symlink = false;

    if let Some(host) = facts {
        match &host.symlink {
            SymlinkResolution::Pending => {
                return Resolution::Unresolved(vec![UnresolvedReason {
                    kind: UnresolvedKind::PendingSymlink,
                    span: Span::from_usize(0, raw.len()),
                    detail: "symlink realpath resolution pending daemon response".into(),
                }]);
            }
            SymlinkResolution::ResolvedSymlink { realpath } => {
                let real_prepared = match prepare_checked_path(realpath) {
                    Ok(prepared) => prepared,
                    Err(reason) => return Resolution::Malformed(reason),
                };
                effective = canonicalize_clean_lex(&real_prepared, is_windows);
                resolved_symlink = true;
            }
            SymlinkResolution::Direct => {}
        }
        if host.volume_case == VolumeCase::CaseInsensitive {
            effective = effective.to_ascii_lowercase();
        }
    }

    if let Some(reason) = check_unresolved_effective(&effective, is_windows, raw.len()) {
        return Resolution::Unresolved(vec![reason]);
    }

    let Some(host) = facts else {
        return Resolution::Unresolved(vec![UnresolvedReason {
            kind: UnresolvedKind::UnknownVariable,
            span: Span::from_usize(0, raw.len()),
            detail: "host PathFacts missing; cannot verify workspace confinement".into(),
        }]);
    };
    let Some(root) = host.workspace_root.as_deref() else {
        return Resolution::Unresolved(vec![UnresolvedReason {
            kind: UnresolvedKind::UnknownVariable,
            span: Span::from_usize(0, raw.len()),
            detail: "workspace_root missing; cannot evaluate workspace confinement".into(),
        }]);
    };

    let (raw_base, ads_stream) = if host.os == OsKind::Windows {
        split_ntfs_ads(&effective)
    } else {
        (effective.as_str(), None)
    };
    let ads_stream = ads_stream.map(str::to_owned);
    let base_without_ads = if host.os == OsKind::Windows {
        let mut clean = canonicalize_clean_lex(raw_base, true);
        if host.volume_case == VolumeCase::CaseInsensitive {
            clean = clean.to_ascii_lowercase();
        }
        clean
    } else {
        raw_base.to_owned()
    };
    if let Some(reason) = check_unresolved_effective(&base_without_ads, is_windows, raw.len()) {
        return Resolution::Unresolved(vec![reason]);
    }
    let lex_base = if host.os == OsKind::Windows {
        let (raw_lex_base, _) = split_ntfs_ads(&lex);
        canonicalize_clean_lex(raw_lex_base, true)
    } else {
        lex
    };

    let norm_root = canonicalize_clean_lex(root, host.os == OsKind::Windows);
    let escaped_workspace = !path_within_workspace(&base_without_ads, &norm_root, host.volume_case);

    let mut classes = classify_protected_path(&base_without_ads);
    if resolved_symlink {
        for cls in classify_protected_path(&lex_base) {
            if !classes.contains(&cls) {
                classes.push(cls);
            }
        }
    }

    Resolution::Resolved(CanonicalPath {
        canonical: effective,
        base_without_ads,
        ads_stream,
        escaped_workspace,
        classes,
    })
}

fn check_unresolved_effective(
    effective: &str,
    is_windows: bool,
    raw_len: usize,
) -> Option<UnresolvedReason> {
    if is_windows && contains_windows_short_name(effective) {
        return Some(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(0, raw_len),
            detail: "windows 8.3 short name requires host realpath resolution".into(),
        });
    }
    if is_tilde_user_path(effective) {
        return Some(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(0, raw_len),
            detail: "tilde user home `~user` requires host directory resolution".into(),
        });
    }
    if is_windows_drive_relative(effective) {
        return Some(UnresolvedReason {
            kind: UnresolvedKind::UnknownVariable,
            span: Span::from_usize(0, raw_len),
            detail: "drive-relative Windows path requires per-drive working directory".into(),
        });
    }
    if has_unresolved_parent_escape(effective) {
        return Some(UnresolvedReason {
            kind: UnresolvedKind::UnknownVariable,
            span: Span::from_usize(0, raw_len),
            detail: "leading parent traversal escapes known root".into(),
        });
    }
    None
}

/// Validates path syntax for NUL, control characters, and malformed UTF-8 in `file://` URIs.
pub(crate) fn validate_path_syntax(raw: &str) -> Result<(), MalformedReason> {
    let _ = prepare_checked_path(raw)?;
    Ok(())
}

/// Returns true if a path relies on unresolved traversal, `~user`, drive-relative, or 8.3 names.
#[must_use]
pub(crate) fn has_unresolved_path_syntax(raw: &str) -> bool {
    let lex = canonicalize_path_lex(raw);
    let win_like =
        raw.contains('\\') || is_windows_drive_head(&lex) || is_windows_drive_relative(&lex);
    let target = if win_like {
        let (base, _) = split_ntfs_ads(&lex);
        Cow::Owned(canonicalize_clean_lex(base, true))
    } else {
        Cow::Borrowed(lex.as_str())
    };
    has_unresolved_parent_escape(&target)
        || is_tilde_user_path(&target)
        || is_windows_drive_relative(&target)
        || contains_windows_short_name(&target)
}

fn prepare_checked_path(raw: &str) -> Result<Cow<'_, str>, MalformedReason> {
    validate_control_chars(raw, raw.len())?;
    let trimmed = raw.trim();
    let prepared = strip_file_scheme(trimmed, true).map_err(|()| {
        MalformedReason::new(
            MalformedKind::InvalidEncoding,
            Span::from_usize(0, raw.len()),
            "invalid UTF-8 sequence inside file URI path",
        )
    })?;
    validate_control_chars(&prepared, raw.len())?;
    Ok(prepared)
}

fn validate_control_chars(text: &str, raw_len: usize) -> Result<(), MalformedReason> {
    if text.contains('\0') || text.chars().any(char::is_control) {
        return Err(MalformedReason::new(
            MalformedKind::SyntaxError,
            Span::from_usize(0, raw_len),
            "NUL or control character rejected in path",
        ));
    }
    Ok(())
}

fn decode_uri_part(raw: &str, strict_utf8: bool) -> Result<String, ()> {
    let bytes = decode_url_percent_once_bytes(raw.as_bytes());
    if strict_utf8 {
        String::from_utf8(bytes).map_err(|_| ())
    } else {
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn strip_file_scheme(trimmed: &str, strict_utf8: bool) -> Result<Cow<'_, str>, ()> {
    let Some(prefix) = trimmed.get(..7) else {
        return Ok(Cow::Borrowed(trimmed));
    };
    if !prefix.eq_ignore_ascii_case("file://") {
        return Ok(Cow::Borrowed(trimmed));
    }
    let rest = trimmed.get(7..).unwrap_or("");
    if rest.chars().next().is_some_and(char::is_whitespace) {
        return decode_uri_part(rest.trim(), strict_utf8).map(Cow::Owned);
    }
    let norm_rest = rest.trim().replace('\\', "/");
    if let Some(after_root) = norm_rest.strip_prefix('/') {
        let stripped = after_root.trim_start_matches('/');
        let decoded = decode_uri_part(stripped, strict_utf8)?;
        if is_windows_drive_head(&decoded) {
            return Ok(Cow::Owned(decoded));
        }
        return Ok(Cow::Owned(format!("/{decoded}")));
    }
    let (auth_raw, tail_raw) = norm_rest.split_once('/').unwrap_or((&norm_rest, ""));
    let auth = decode_uri_part(auth_raw, strict_utf8)?;
    let tail = decode_uri_part(tail_raw, strict_utf8)?;
    if auth.eq_ignore_ascii_case("localhost") {
        let clean_tail = tail.trim_start_matches('/');
        if clean_tail.is_empty() {
            return Ok(Cow::Owned("/".to_owned()));
        }
        if is_windows_drive_head(clean_tail) {
            return Ok(Cow::Owned(clean_tail.to_owned()));
        }
        return Ok(Cow::Owned(format!("/{clean_tail}")));
    }
    if tail.is_empty() {
        Ok(Cow::Owned(format!("//{auth}")))
    } else {
        Ok(Cow::Owned(format!("//{auth}/{tail}")))
    }
}

fn canonicalize_clean_lex(input: &str, windows_mode: bool) -> String {
    let trimmed = input.trim();
    let without_scheme = strip_file_scheme(trimmed, false).unwrap_or(Cow::Borrowed(trimmed));
    let nfc: String = without_scheme.nfc().collect();
    let has_win_backslash = nfc.contains('\\');
    let mut current = nfc.replace('\\', "/");
    for _ in 0..4 {
        let next = canonicalize_clean_lex_pass(&current, windows_mode || has_win_backslash);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn canonicalize_clean_lex_pass(raw_slashed: &str, force_win_dots: bool) -> String {
    let mut slashed = raw_slashed.to_owned();
    loop {
        if slashed
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("//?/unc/"))
        {
            let tail = slashed.get(8..).unwrap_or("").trim_start_matches('/');
            slashed = format!("//{tail}");
            continue;
        }
        if let Some(dev) = slashed.strip_prefix("//?/")
            && (is_windows_drive_head(dev)
                || dev.starts_with("//?/")
                || dev
                    .get(..8)
                    .is_some_and(|p| p.eq_ignore_ascii_case("//?/unc/")))
        {
            slashed = dev.to_owned();
            continue;
        }
        break;
    }
    if !slashed.starts_with("//./") && !slashed.starts_with("//?/") && slashed.starts_with("///") {
        slashed = format!("/{}", slashed.trim_start_matches('/'));
    }

    let strip_win_dots = force_win_dots
        || is_windows_drive_head(&slashed)
        || is_windows_drive_relative(&slashed)
        || slashed.starts_with("//");
    let (prefix, rest) = extract_path_root(&slashed);
    let is_rooted = !prefix.is_empty() && prefix != "~/" && !is_windows_drive_relative(&prefix);

    let mut stack: Vec<String> = Vec::new();
    for segment in rest.split('/') {
        let norm_seg = if strip_win_dots {
            strip_trailing_win_dots_and_spaces(segment)
        } else {
            segment
        };
        match norm_seg {
            "" | "." => {}
            ".." => {
                let can_pop = stack.last().is_some_and(|last| last.trim_end() != "..");
                if can_pop {
                    let _ = stack.pop();
                } else if !is_rooted {
                    stack.push("..".to_owned());
                }
            }
            other => stack.push(other.to_owned()),
        }
    }

    let head = resolve_boundary_segments(&prefix, is_rooted, &mut stack);
    let slice = stack.get(head..).unwrap_or(&[]);
    if prefix.is_empty() && slice.is_empty() {
        return ".".into();
    }
    let joined = slice.join("/");
    if prefix.is_empty() {
        let final_joined = joined.trim();
        if final_joined.is_empty() {
            ".".into()
        } else {
            final_joined.to_string()
        }
    } else {
        let final_joined = joined.trim_end();
        if final_joined.is_empty() {
            prefix
        } else {
            format!("{prefix}{final_joined}")
        }
    }
}

fn strip_trailing_win_dots_and_spaces(segment: &str) -> &str {
    if segment == "." || segment == ".." || segment.trim().is_empty() {
        return segment;
    }
    let trimmed = segment.trim_end_matches(['.', ' ']);
    if trimmed.is_empty() { segment } else { trimmed }
}

fn extract_path_root(slashed: &str) -> (String, &str) {
    if let Some(rest) = slashed.strip_prefix("~/") {
        return ("~/".into(), rest);
    }
    if let Some(rest) = slashed.strip_prefix("//./") {
        return ("//./".into(), rest);
    }
    if let Some(rest) = slashed.strip_prefix("//?/") {
        return ("//?/".into(), rest);
    }
    if let Some(after) = slashed.strip_prefix("//") {
        if let Some((srv, tail_raw)) = after.split_once('/')
            && !srv.is_empty()
            && srv != "."
            && srv != ".."
        {
            let tail_srv = tail_raw.trim_start_matches('/');
            if let Some((share, rest)) = tail_srv.split_once('/')
                && !share.is_empty()
                && share != "."
                && share != ".."
            {
                return (format!("//{srv}/{share}/"), rest);
            }
            if !tail_srv.is_empty()
                && !tail_srv.contains('/')
                && tail_srv != "."
                && tail_srv != ".."
            {
                return (format!("//{srv}/{tail_srv}/"), "");
            }
        }
        return ("//".into(), after);
    }
    if let Some(rest) = slashed.strip_prefix('/') {
        return ("/".into(), rest);
    }
    let mut chars = slashed.chars();
    if let (Some(drive), Some(':'), third) = (chars.next(), chars.next(), chars.next())
        && drive.is_ascii_alphabetic()
    {
        if third == Some('/') {
            let prefix = format!("{drive}:/");
            let rest = slashed.strip_prefix(&prefix).unwrap_or("");
            return (prefix, rest);
        }
        let prefix = format!("{drive}:");
        let rest = slashed.get(2..).unwrap_or("");
        return (prefix, rest);
    }
    (String::new(), slashed)
}

fn resolve_boundary_segments(prefix: &str, is_rooted: bool, stack: &mut Vec<String>) -> usize {
    let mut head: usize = 0;
    loop {
        let mut changed = false;
        while stack.len() > head {
            let Some(tail) = stack.last() else {
                break;
            };
            let trimmed_tail = if prefix.is_empty() && stack.len().saturating_sub(head) == 1 {
                tail.trim()
            } else {
                tail.trim_end()
            };
            match trimmed_tail {
                "" | "." => {
                    let _ = stack.pop();
                    changed = true;
                }
                ".." => {
                    let before_tail = stack
                        .len()
                        .checked_sub(2)
                        .and_then(|idx| if idx >= head { stack.get(idx) } else { None })
                        .map(|s| s.trim_end() != "..")
                        .unwrap_or(false);
                    if before_tail {
                        let _ = stack.pop();
                        let _ = stack.pop();
                        changed = true;
                    } else if is_rooted {
                        let _ = stack.pop();
                        changed = true;
                    } else {
                        if tail != ".." {
                            if let Some(slot) = stack.last_mut() {
                                *slot = "..".to_owned();
                            }
                            changed = true;
                        }
                        break;
                    }
                }
                _ => break,
            }
        }
        if prefix.is_empty()
            && let Some(first) = stack.get(head)
            && matches!(first.trim_start(), "" | ".")
        {
            head = head.saturating_add(1);
            changed = true;
        }
        if !changed {
            break;
        }
    }
    head
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_facts(ws: Option<&str>) -> PathFacts {
        PathFacts {
            os: OsKind::Linux,
            volume_case: VolumeCase::CaseSensitive,
            symlink: SymlinkResolution::Direct,
            workspace_root: ws.map(str::to_owned),
        }
    }

    #[test]
    fn rejects_nul_and_control_bytes_and_truncates_lex() {
        assert!(
            resolve_path("/tmp/a\0/../.ssh/id_rsa", Some(&linux_facts(Some("/ws")))).is_malformed()
        );
        assert!(resolve_path("file:///tmp/%00/x", Some(&linux_facts(Some("/ws")))).is_malformed());
        assert_eq!(canonicalize_path_lex("/safe/\0/../.ssh/id_rsa"), "/safe");
    }

    #[test]
    fn preserves_relative_and_home_parent_traversal_and_device_roots() {
        assert_eq!(
            canonicalize_path_lex("~/../.ssh/id_rsa"),
            "~/../.ssh/id_rsa"
        );
        assert_eq!(
            canonicalize_path_lex("../../.claude/settings.json"),
            "../../.claude/settings.json"
        );
        assert_eq!(canonicalize_path_lex("./   /foo"), "foo");
        assert_eq!(
            canonicalize_path_lex(r"\\.\pipe\docker_engine"),
            "//./pipe/docker_engine"
        );
        assert_eq!(
            canonicalize_path_lex(r"\\srv\share\a\..\..\etc"),
            "//srv/share/etc"
        );
        assert_eq!(
            canonicalize_path_lex("FILE://localhost/C:/Users/dev/../key.pem"),
            "C:/Users/key.pem"
        );
        assert_eq!(
            canonicalize_path_lex("file:///home/dev/%2e%2e/.ssh/id_rsa"),
            "/home/.ssh/id_rsa"
        );
    }

    #[test]
    fn enforces_segment_boundary_and_windows_only_ads_and_short_names() {
        let outside = resolve_path("/ws_evil/secret", Some(&linux_facts(Some("/ws"))));
        let Resolution::Resolved(out_cp) = outside else {
            panic!("expected resolved absolute path");
        };
        assert!(out_cp.escaped_workspace);

        let posix_colon = resolve_path("/ws/file:not_ads", Some(&linux_facts(Some("/ws"))));
        let Resolution::Resolved(posix_cp) = posix_colon else {
            panic!("expected resolved posix path");
        };
        assert!(posix_cp.ads_stream.is_none());

        assert!(resolve_path("/ws/file", None).is_unresolved());
        assert!(
            resolve_path(
                r"C:\PROGRA~1\secret",
                Some(&PathFacts {
                    os: OsKind::Windows,
                    volume_case: VolumeCase::CaseInsensitive,
                    symlink: SymlinkResolution::Direct,
                    workspace_root: Some("C:/ws".into()),
                })
            )
            .is_unresolved()
        );
        assert!(resolve_path("~/../.ssh/id_rsa", Some(&linux_facts(Some("/ws")))).is_unresolved());
    }

    #[test]
    fn unions_symlink_target_and_link_protected_classes() {
        let res = resolve_path(
            "/ws/.claude/settings.json",
            Some(&PathFacts {
                os: OsKind::Linux,
                volume_case: VolumeCase::CaseSensitive,
                symlink: SymlinkResolution::ResolvedSymlink {
                    realpath: "/outside/.ssh/id_rsa".into(),
                },
                workspace_root: Some("/ws".into()),
            }),
        );
        let Resolution::Resolved(cp) = res else {
            panic!("expected resolved symlink");
        };
        assert!(cp.escaped_workspace);
        assert!(cp.classes.contains(&ProtectedPathClass::PrivateKey));
        assert!(cp.classes.contains(&ProtectedPathClass::AgentControl));
    }

    #[test]
    fn detects_expanded_protected_classes_and_redacts_debug() {
        assert!(
            classify_protected_path("/home/dev/.bashrc").contains(&ProtectedPathClass::Autorun)
        );
        assert!(classify_protected_path("/ws/.env").contains(&ProtectedPathClass::CredStore));
        assert!(
            classify_protected_path("/private/var/folders/xx/yy")
                .contains(&ProtectedPathClass::SessionTmp)
        );
        let dbg = format!(
            "{:?}",
            CanonicalPath {
                canonical: "/secret/user/token".into(),
                base_without_ads: "/secret/user/token".into(),
                ads_stream: None,
                escaped_workspace: true,
                classes: vec![],
            }
        );
        assert!(!dbg.contains("/secret/user/token"));
    }

    #[test]
    fn round2_handles_tilde_user_drive_relative_file_uris_and_new_classes() {
        assert!(resolve_path("~root/.ssh/id_rsa", Some(&linux_facts(Some("/ws")))).is_unresolved());
        assert!(
            resolve_path(
                "C:../../secret",
                Some(&PathFacts {
                    os: OsKind::Windows,
                    volume_case: VolumeCase::CaseInsensitive,
                    symlink: SymlinkResolution::Direct,
                    workspace_root: Some("C:/ws".into()),
                })
            )
            .is_unresolved()
        );
        assert_eq!(canonicalize_path_lex("C:../../secret."), "C:../../secret");
        assert_eq!(
            canonicalize_path_lex("C:/Users/dev/.ssh/id_rsa. "),
            "C:/Users/dev/.ssh/id_rsa"
        );
        assert_eq!(
            canonicalize_path_lex(r"file://\C:\Users\dev"),
            "C:/Users/dev"
        );
        assert_eq!(canonicalize_path_lex("file:////etc/passwd"), "/etc/passwd");
        assert!(has_unresolved_path_syntax("C:secret"));
        assert!(has_unresolved_path_syntax("~alice/.env"));
        assert!(has_unresolved_path_syntax("../../etc/passwd"));

        let symlink_83 = resolve_path(
            r"C:\ws\ok",
            Some(&PathFacts {
                os: OsKind::Windows,
                volume_case: VolumeCase::CaseInsensitive,
                symlink: SymlinkResolution::ResolvedSymlink {
                    realpath: r"C:\PROGRA~1\secret".into(),
                },
                workspace_root: Some("C:/ws".into()),
            }),
        );
        assert!(symlink_83.is_unresolved());

        assert!(
            classify_protected_path("/ws/.git/hooks").contains(&ProtectedPathClass::AgentControl)
        );
        assert!(classify_protected_path("/ws/.cursor").contains(&ProtectedPathClass::AgentControl));
        assert!(classify_protected_path("/etc/profile.d").contains(&ProtectedPathClass::Autorun));
        assert!(classify_protected_path("/etc/rc.local").contains(&ProtectedPathClass::Autorun));
        assert!(
            classify_protected_path("/home/dev/.config/autostart")
                .contains(&ProtectedPathClass::Autorun)
        );
        assert!(classify_protected_path("/private/tmp").contains(&ProtectedPathClass::SessionTmp));
        assert!(classify_protected_path("/var/tmp").contains(&ProtectedPathClass::SessionTmp));
    }

    #[test]
    fn round4_ntfs_ads_relative_win_dots_and_nt_device_paths() {
        let win_facts = PathFacts {
            os: OsKind::Windows,
            volume_case: VolumeCase::CaseInsensitive,
            symlink: SymlinkResolution::Direct,
            workspace_root: Some("C:/ws".into()),
        };

        let ads_escape = resolve_path(r"C:\ws\..:$DATA", Some(&win_facts));
        let Resolution::Resolved(ads_escape_cp) = ads_escape else {
            panic!("expected resolved ADS escape");
        };
        assert!(ads_escape_cp.escaped_workspace);

        let ads_agents = resolve_path(r"C:\ws\AGENTS.md.:$DATA", Some(&win_facts));
        let Resolution::Resolved(ads_agents_cp) = ads_agents else {
            panic!("expected resolved ADS AGENTS.md");
        };
        assert!(!ads_agents_cp.escaped_workspace);
        assert!(
            ads_agents_cp
                .classes
                .contains(&ProtectedPathClass::AgentControl)
        );

        assert!(resolve_path(r"..:$DATA", Some(&win_facts)).is_unresolved());

        let rel_win = canonicalize_path_lex(r"ws\.claude. ");
        assert_eq!(rel_win, "ws/.claude");
        assert_eq!(canonicalize_path_lex(&rel_win), rel_win);

        let dev_dots = canonicalize_path_lex("//./C:/ws/.claude. ");
        assert_eq!(dev_dots, "//./C:/ws/.claude");
        assert_eq!(canonicalize_path_lex(&dev_dots), dev_dots);

        let double_nt = canonicalize_path_lex("//?///?/a");
        assert_eq!(canonicalize_path_lex(&double_nt), double_nt);
        assert_eq!(
            canonicalize_path_lex("//?///?/UNC/srv/share"),
            "//srv/share/"
        );

        for nt_path in [
            r"\\?\Volume{1234-5678}\secret",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\secret",
        ] {
            let res = resolve_path(nt_path, Some(&win_facts));
            let Resolution::Resolved(cp) = res else {
                panic!("expected resolved NT device path for {nt_path}");
            };
            assert!(cp.escaped_workspace, "expected escape for {nt_path}");
            assert!(cp.canonical.starts_with("//?/"));
        }
    }

    #[test]
    fn round5_nt_and_unc_paths_converge_idempotently_in_single_call() {
        for (raw, expected) in [
            ("//?//C:/a", "C:/a"),
            ("//?/./C:/a", "C:/a"),
            ("//?/a/../C:/a", "C:/a"),
            ("//?//UNC/srv/share", "//srv/share/"),
            ("//?/./UNC/srv/share", "//srv/share/"),
            ("//?/C:.", "C:"),
            ("//a/./b", "//a/b/"),
            ("//../a/b", "//a/b/"),
        ] {
            let once = canonicalize_path_lex(raw);
            assert_eq!(once, expected, "unexpected pass-1 canonical for {raw}");
            assert_eq!(
                canonicalize_path_lex(&once),
                once,
                "canonicalize_path_lex not idempotent for {raw}"
            );
        }

        let win_facts = PathFacts {
            os: OsKind::Windows,
            volume_case: VolumeCase::CaseInsensitive,
            symlink: SymlinkResolution::Direct,
            workspace_root: Some("C:/ws".into()),
        };
        let dot_nt = resolve_path(r"\\?\.\C:\ws\AGENTS.md", Some(&win_facts));
        let Resolution::Resolved(dot_cp) = dot_nt else {
            panic!("expected resolved \\\\?\\.\\C:\\... path");
        };
        assert_eq!(dot_cp.base_without_ads, "c:/ws/agents.md");
        assert!(!dot_cp.escaped_workspace);
        assert!(dot_cp.classes.contains(&ProtectedPathClass::AgentControl));
    }
}
