// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::MacOsSensorError;
use crate::catalogue::HarnessCatalogue;

const MAX_SESSION_ID_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacOsContainmentMode {
    Delegate,
    WrapAgent,
    WrapTools,
    RequestOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatbeltProfileSpec {
    pub session_id: String,
    pub workspace_root: String,
    pub state_dirs: Vec<String>,
    pub protected_paths: Vec<String>,
    pub decide_socket_path: String,
    pub proxy_port: u16,
    pub deny_elevation_binaries: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatbeltLaunchPlan {
    pub containment_mode: MacOsContainmentMode,
    pub visibility_is_claimed: bool,
    pub on_failure_closed: bool,
    pub profile_sbpl: Option<String>,
    pub reason: String,
}

pub fn canonicalize_macos_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed == "/tmp" || trimmed.starts_with("/tmp/") {
        return format!("/private{trimmed}");
    }
    if trimmed == "/var" || trimmed.starts_with("/var/") {
        return format!("/private{trimmed}");
    }
    if trimmed == "/etc" || trimmed.starts_with("/etc/") {
        return format!("/private{trimmed}");
    }
    trimmed.to_string()
}

pub fn scoped_session_tmp_dir(session_id: &str) -> Result<String, MacOsSensorError> {
    let clean = sanitize_session_slug(session_id)?;
    let root = resolve_unix_tmp_base();
    let candidate = format!("{root}/grdr-sessions/{clean}/tmp");
    let canon = validate_and_escape_sbpl_path("session_tmp_dir", &candidate)?;
    reject_shared_tmp_root(&canon)?;
    Ok(canon)
}

pub fn ensure_scoped_session_tmp_dir(canon_tmp_dir: &str) -> Result<PathBuf, MacOsSensorError> {
    let clean = validate_and_escape_sbpl_path("session_tmp_dir", canon_tmp_dir)?;
    reject_shared_tmp_root(&clean)?;
    let target = PathBuf::from(&clean);
    for anc in target.ancestors() {
        if anc.as_os_str().is_empty() {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(anc)
            && meta.file_type().is_symlink()
        {
            return Err(MacOsSensorError::Seatbelt(format!(
                "refusing symlink component `{}` in scoped session tmp",
                anc.display()
            )));
        }
    }
    #[cfg(unix)]
    {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(&target).map_err(|err| {
            MacOsSensorError::Seatbelt(format!(
                "failed creating scoped session tmp `{}`: {err}",
                target.display()
            ))
        })?;
        // Verify final directory itself is a real non-symlink directory via O_NOFOLLOW.
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).custom_flags(libc::O_NOFOLLOW);
        let fd = opts.open(&target).map_err(|err| {
            MacOsSensorError::Seatbelt(format!(
                "failed opening scoped session tmp `{}`: {err}",
                target.display()
            ))
        })?;
        let meta = fd.metadata().map_err(|err| {
            MacOsSensorError::Seatbelt(format!("failed inspecting scoped session tmp: {err}"))
        })?;
        if !meta.file_type().is_dir() {
            return Err(MacOsSensorError::Seatbelt(
                "scoped session tmp path is not a real directory".into(),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&target).map_err(|err| {
            MacOsSensorError::Seatbelt(format!(
                "failed creating scoped session tmp `{}`: {err}",
                target.display()
            ))
        })?;
    }
    Ok(target)
}

pub fn generate_sbpl_profile(spec: &SeatbeltProfileSpec) -> Result<String, MacOsSensorError> {
    let scoped_tmp = scoped_session_tmp_dir(&spec.session_id)?;
    let env_home = std::env::var("HOME").ok();
    generate_sbpl_profile_with_options(spec, &scoped_tmp, env_home.as_deref())
}

pub fn generate_sbpl_profile_with_tmp(
    spec: &SeatbeltProfileSpec,
    session_tmp_dir: &str,
) -> Result<String, MacOsSensorError> {
    let env_home = std::env::var("HOME").ok();
    generate_sbpl_profile_with_options(spec, session_tmp_dir, env_home.as_deref())
}

pub fn generate_sbpl_profile_with_options(
    spec: &SeatbeltProfileSpec,
    session_tmp_dir: &str,
    home_dir: Option<&str>,
) -> Result<String, MacOsSensorError> {
    let workspace = validate_and_escape_sbpl_path("workspace_root", &spec.workspace_root)?;
    let decide_sock =
        validate_and_escape_sbpl_path("decide_socket_path", &spec.decide_socket_path)?;
    let scoped_tmp = validate_and_escape_sbpl_path("session_tmp_dir", session_tmp_dir)?;
    reject_shared_tmp_root(&scoped_tmp)?;

    let mut lines = vec![
        "(version 1)".to_string(),
        "(deny default)".to_string(),
        "(allow process-exec*)".to_string(),
        "(allow process-fork)".to_string(),
        "(allow sysctl-read)".to_string(),
        "(allow file-read-metadata)".to_string(),
        "(allow signal (target self))".to_string(),
        "(allow file-read*)".to_string(),
        format!("(allow file-write* (subpath \"{workspace}\"))"),
        format!("(allow file-write* (subpath \"{scoped_tmp}\"))"),
    ];

    for dir in &spec.state_dirs {
        let resolved = resolve_state_dir_for_sbpl(dir, home_dir)?;
        let canon = validate_and_escape_sbpl_path("state_dirs", &resolved)?;
        lines.push(format!("(allow file-write* (subpath \"{canon}\"))"));
    }

    for protected in &spec.protected_paths {
        let canon = validate_and_escape_sbpl_path("protected_paths", protected)?;
        lines.push(format!(
            "(deny file-read* file-write* (subpath \"{canon}\"))"
        ));
    }

    if spec.deny_elevation_binaries {
        for bin in ["/usr/bin/sudo", "/usr/bin/su", "/bin/launchctl"] {
            lines.push(format!("(deny process-exec (literal \"{bin}\"))"));
        }
        lines.push(
            "(deny network-outbound (remote unix-socket (path-literal \"/private/var/run/docker.sock\")))"
                .into(),
        );
    }

    lines.push("(deny network*)".into());
    lines.push(format!(
        "(allow network-outbound (remote unix-socket (path-literal \"{decide_sock}\")))"
    ));
    if spec.proxy_port > 0 {
        lines.push(format!(
            "(allow network-outbound (remote ip \"{}:{}\"))",
            Ipv4Addr::LOCALHOST,
            spec.proxy_port
        ));
    }

    Ok(lines.join("\n"))
}

pub fn plan_macos_launch(
    agent_kind: &str,
    agent_has_own_seatbelt: bool,
    spec: &SeatbeltProfileSpec,
) -> Result<SeatbeltLaunchPlan, MacOsSensorError> {
    plan_macos_launch_with_catalogue(
        agent_kind,
        agent_has_own_seatbelt,
        spec,
        HarnessCatalogue::embedded(),
    )
}

pub fn plan_macos_launch_with_catalogue(
    agent_kind: &str,
    agent_has_own_seatbelt: bool,
    spec: &SeatbeltProfileSpec,
    catalogue: &HarnessCatalogue,
) -> Result<SeatbeltLaunchPlan, MacOsSensorError> {
    if catalogue.should_delegate_seatbelt(agent_kind, agent_has_own_seatbelt) {
        return Ok(SeatbeltLaunchPlan {
            containment_mode: MacOsContainmentMode::Delegate,
            visibility_is_claimed: true,
            on_failure_closed: true,
            profile_sbpl: None,
            reason:
                "delegating to agent's locked Seatbelt sandbox to avoid nested Seatbelt conflict"
                    .into(),
        });
    }
    if agent_has_own_seatbelt {
        let sbpl = generate_sbpl_profile(spec)?;
        return Ok(SeatbeltLaunchPlan {
            containment_mode: MacOsContainmentMode::WrapTools,
            visibility_is_claimed: true,
            on_failure_closed: true,
            profile_sbpl: Some(sbpl),
            reason: "tool subprocesses rewritten through grdr-run Seatbelt profile".into(),
        });
    }
    let sbpl = generate_sbpl_profile(spec)?;
    Ok(SeatbeltLaunchPlan {
        containment_mode: MacOsContainmentMode::WrapAgent,
        visibility_is_claimed: true,
        on_failure_closed: true,
        profile_sbpl: Some(sbpl),
        reason: "whole-agent Seatbelt launch via grdr-run".into(),
    })
}

fn resolve_state_dir_for_sbpl(
    raw: &str,
    home_dir: Option<&str>,
) -> Result<String, MacOsSensorError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(MacOsSensorError::Seatbelt(format!(
            "state_dirs `{raw}` cannot be empty or contain control characters"
        )));
    }
    if trimmed.starts_with('/') {
        return Ok(trimmed.to_string());
    }
    if trimmed.starts_with('~') || trimmed.starts_with('$') {
        return Err(MacOsSensorError::Seatbelt(format!(
            "state_dirs `{raw}` must be resolved rather than unexpanded `{trimmed}`"
        )));
    }
    if trimmed
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(MacOsSensorError::Seatbelt(format!(
            "state_dirs `{raw}` contains invalid relative path segments"
        )));
    }
    let Some(home_raw) = home_dir.map(str::trim).filter(|h| h.starts_with('/')) else {
        return Err(MacOsSensorError::Seatbelt(format!(
            "relative state_dirs `{raw}` requires an absolute POSIX HOME directory"
        )));
    };
    if home_raw.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(MacOsSensorError::Seatbelt(
            "HOME contains NUL or control characters".into(),
        ));
    }
    let base = home_raw.trim_end_matches('/');
    if base.is_empty() {
        return Err(MacOsSensorError::Seatbelt(
            "HOME cannot resolve to filesystem root `/`".into(),
        ));
    }
    Ok(format!("{base}/{trimmed}"))
}

fn resolve_unix_tmp_base() -> String {
    for var in ["GRDR_SESSION_TMP_ROOT", "XDG_RUNTIME_DIR", "TMPDIR"] {
        if let Ok(val) = std::env::var(var) {
            let trimmed = val.trim().trim_end_matches('/');
            if trimmed.starts_with('/') && !trimmed.contains('\0') && !trimmed.contains("..") {
                return canonicalize_macos_path(trimmed);
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let trimmed = home.trim().trim_end_matches('/');
        if trimmed.starts_with('/') && !trimmed.contains('\0') && !trimmed.contains("..") {
            return format!("{}/.cache", canonicalize_macos_path(trimmed));
        }
    }
    "/private/var/tmp".to_string()
}

fn sanitize_session_slug(raw: &str) -> Result<&str, MacOsSensorError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_SESSION_ID_LEN
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains("..")
    {
        return Err(MacOsSensorError::Seatbelt(
            "session_id must be non-empty and within 128 characters".into(),
        ));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(MacOsSensorError::Seatbelt(
            "session_id contains forbidden path or SBPL characters".into(),
        ));
    }
    Ok(trimmed)
}

fn reject_shared_tmp_root(canon_path: &str) -> Result<(), MacOsSensorError> {
    let trimmed = canon_path.trim_end_matches('/');
    if trimmed == "/tmp"
        || trimmed == "/private/tmp"
        || trimmed == "/var/tmp"
        || trimmed == "/private/var/tmp"
    {
        return Err(MacOsSensorError::Seatbelt(
            "session_tmp_dir cannot grant broad shared temp root write access".into(),
        ));
    }
    Ok(())
}

fn validate_and_escape_sbpl_path(field: &str, raw: &str) -> Result<String, MacOsSensorError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return Err(MacOsSensorError::Seatbelt(format!(
            "{field} `{raw}` must be a non-empty absolute path"
        )));
    }
    if trimmed.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(MacOsSensorError::Seatbelt(format!(
            "{field} contains forbidden NUL or control characters"
        )));
    }
    if trimmed
        .split('/')
        .skip(1)
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(MacOsSensorError::Seatbelt(format!(
            "{field} `{raw}` contains invalid `.`, `..`, or empty segments"
        )));
    }
    let canon = canonicalize_macos_path(trimmed);
    Ok(canon.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::{DelegationPolicy, HarnessEntry, NativeSandboxKind};

    #[test]
    fn canonicalizes_tmp_var_resolves_relative_state_dirs_and_generates_sbpl() {
        assert_eq!(canonicalize_macos_path("/tmp/ws"), "/private/tmp/ws");
        assert_eq!(
            canonicalize_macos_path("/var/run/docker.sock"),
            "/private/var/run/docker.sock"
        );

        let spec = SeatbeltProfileSpec {
            session_id: "sess-sb-mac".into(),
            workspace_root: "/tmp/project".into(),
            state_dirs: vec![".claude".into(), ".codex".into()],
            protected_paths: vec!["/Users/dev/.ssh".into()],
            decide_socket_path: "/Library/Application Support/grdr/run/decide.sock".into(),
            proxy_port: 41234,
            deny_elevation_binaries: true,
        };
        let sbpl = generate_sbpl_profile_with_options(
            &spec,
            "/Users/dev/.cache/grdr-sessions/sess-sb-mac/tmp",
            Some("/Users/dev"),
        )
        .unwrap();
        assert!(sbpl.contains("/private/tmp/project"));
        assert!(sbpl.contains("(allow file-write* (subpath \"/Users/dev/.claude\"))"));
        assert!(sbpl.contains("(allow file-write* (subpath \"/Users/dev/.codex\"))"));
        assert!(sbpl.contains("(allow process-fork)"));
        assert!(sbpl.contains("(allow sysctl-read)"));
        assert!(sbpl.contains("(allow file-read-metadata)"));
        assert!(sbpl.contains("(allow signal (target self))"));
        assert!(!sbpl.contains("(allow file-write* (subpath \"/private/tmp\"))"));
        assert!(sbpl.contains("(deny network*)"));
        assert!(sbpl.contains("127.0.0.1:41234"));
        assert!(sbpl.contains("/usr/bin/sudo"));

        let abs_spec = SeatbeltProfileSpec {
            state_dirs: vec!["/Users/dev/.claude".into()],
            ..spec.clone()
        };
        let plan = plan_macos_launch("claude-code", true, &abs_spec).unwrap();
        assert_eq!(plan.containment_mode, MacOsContainmentMode::Delegate);
        assert!(plan.visibility_is_claimed);
        assert!(plan.on_failure_closed);

        let codex_unboxed = plan_macos_launch("codex", false, &abs_spec).unwrap();
        assert_eq!(
            codex_unboxed.containment_mode,
            MacOsContainmentMode::WrapAgent
        );
        assert!(codex_unboxed.profile_sbpl.is_some());

        let custom_catalogue = HarnessCatalogue::from_harnesses(vec![HarnessEntry {
            id: "ext-native".into(),
            aliases: vec![],
            binaries: vec!["ext-native".into()],
            cmdline_markers: vec![],
            signing_ids: vec![],
            team_ids: vec![],
            native_sandbox: NativeSandboxKind::Seatbelt,
            delegation_mode: DelegationPolicy::Delegate,
            model_hosts: vec![],
            state_dirs: vec![],
            config_paths: vec![],
            admin_config_path_macos: None,
            transcript_dirs: vec![],
        }])
        .unwrap();
        let custom_plan =
            plan_macos_launch_with_catalogue("ext-native", true, &abs_spec, &custom_catalogue)
                .expect("custom catalogue plan");
        assert_eq!(custom_plan.containment_mode, MacOsContainmentMode::Delegate);

        let mut quoted_spec = abs_spec;
        quoted_spec.state_dirs = vec![r#"/Users/dev/dir "quoted"\sub"#.into()];
        let quoted_sbpl = generate_sbpl_profile(&quoted_spec).unwrap();
        assert!(quoted_sbpl.contains(r#"/Users/dev/dir \"quoted\"\\sub"#));
    }

    #[test]
    fn rejects_sbpl_nul_newline_traversal_empty_and_broad_tmp() {
        let base = SeatbeltProfileSpec {
            session_id: "sess-bad".into(),
            workspace_root: "/Users/dev/repo".into(),
            state_dirs: vec![],
            protected_paths: vec![],
            decide_socket_path: "/Library/Application Support/grdr/run/decide.sock".into(),
            proxy_port: 49999,
            deny_elevation_binaries: true,
        };

        assert!(generate_sbpl_profile_with_tmp(&base, "/private/tmp").is_err());
        assert!(generate_sbpl_profile_with_tmp(&base, "/tmp").is_err());

        let mut rel_bad = base.clone();
        rel_bad.state_dirs = vec!["../escape".into()];
        assert!(
            generate_sbpl_profile_with_options(
                &rel_bad,
                "/Users/dev/.cache/grdr-sessions/sess-bad/tmp",
                Some("/Users/dev"),
            )
            .is_err()
        );

        let mut rel_no_home = base.clone();
        rel_no_home.state_dirs = vec![".claude".into()];
        assert!(
            generate_sbpl_profile_with_options(
                &rel_no_home,
                "/Users/dev/.cache/grdr-sessions/sess-bad/tmp",
                None,
            )
            .is_err()
        );

        let mut bad_sid = base.clone();
        bad_sid.session_id = "../escape".into();
        assert!(generate_sbpl_profile(&bad_sid).is_err());

        let mut nul_spec = base.clone();
        nul_spec.workspace_root = "/Users/dev/repo\0evil".into();
        assert!(matches!(
            generate_sbpl_profile(&nul_spec),
            Err(MacOsSensorError::Seatbelt(_))
        ));

        let mut newline_spec = base.clone();
        newline_spec.state_dirs = vec!["/Users/dev\n(allow network*)".into()];
        assert!(matches!(
            generate_sbpl_profile(&newline_spec),
            Err(MacOsSensorError::Seatbelt(_))
        ));

        let mut traversal_spec = base.clone();
        traversal_spec.protected_paths = vec!["/Users/dev/../etc".into()];
        assert!(matches!(
            generate_sbpl_profile(&traversal_spec),
            Err(MacOsSensorError::Seatbelt(_))
        ));

        let mut empty_dir_spec = base;
        empty_dir_spec.state_dirs = vec!["".into()];
        assert!(matches!(
            generate_sbpl_profile(&empty_dir_spec),
            Err(MacOsSensorError::Seatbelt(_))
        ));
    }
}
