// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::MacOsSensorError;

pub const DEFAULT_PROXY_LOOPBACK_PORT: u16 = 18080;

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

pub fn generate_sbpl_profile(spec: &SeatbeltProfileSpec) -> Result<String, MacOsSensorError> {
    let workspace = validate_and_escape_sbpl_path("workspace_root", &spec.workspace_root)?;
    let decide_sock =
        validate_and_escape_sbpl_path("decide_socket_path", &spec.decide_socket_path)?;

    let mut lines = vec![
        "(version 1)".to_string(),
        "(deny default)".to_string(),
        "(allow process-exec*)".to_string(),
        "(allow file-read*)".to_string(),
        format!("(allow file-write* (subpath \"{workspace}\"))"),
        "(allow file-write* (subpath \"/private/tmp\"))".to_string(),
    ];

    for dir in &spec.state_dirs {
        let canon = validate_and_escape_sbpl_path("state_dirs", dir)?;
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
        lines.push("(deny network-outbound (remote unix-socket (path-literal \"/private/var/run/docker.sock\")))".into());
    }

    lines.push("(deny network*)".into());
    lines.push(format!(
        "(allow network-outbound (remote unix-socket (path-literal \"{decide_sock}\")))"
    ));
    if spec.proxy_port > 0 {
        lines.push(format!(
            "(allow network-outbound (remote ip \"localhost:{}\"))",
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
    let lower = agent_kind.trim().to_ascii_lowercase();
    if (lower == "codex" || lower == "claude-code") && agent_has_own_seatbelt {
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

    #[test]
    fn canonicalizes_tmp_var_and_generates_fail_closed_sbpl() {
        assert_eq!(canonicalize_macos_path("/tmp/ws"), "/private/tmp/ws");
        assert_eq!(
            canonicalize_macos_path("/var/run/docker.sock"),
            "/private/var/run/docker.sock"
        );

        let spec = SeatbeltProfileSpec {
            session_id: "sess-sb-mac".into(),
            workspace_root: "/tmp/project".into(),
            state_dirs: vec!["/Users/dev/.claude".into()],
            protected_paths: vec!["/Users/dev/.ssh".into()],
            decide_socket_path: "/Library/Application Support/grdr/run/decide.sock".into(),
            proxy_port: DEFAULT_PROXY_LOOPBACK_PORT,
            deny_elevation_binaries: true,
        };
        let sbpl = generate_sbpl_profile(&spec).unwrap();
        assert!(sbpl.contains("/private/tmp/project"));
        assert!(sbpl.contains("(deny network*)"));
        assert!(sbpl.contains("localhost:18080"));
        assert!(sbpl.contains("/usr/bin/sudo"));

        let plan = plan_macos_launch("claude-code", true, &spec).unwrap();
        assert_eq!(plan.containment_mode, MacOsContainmentMode::Delegate);
        assert!(plan.visibility_is_claimed);
        assert!(plan.on_failure_closed);

        let codex_unboxed = plan_macos_launch("codex", false, &spec).unwrap();
        assert_eq!(
            codex_unboxed.containment_mode,
            MacOsContainmentMode::WrapAgent
        );
        assert!(codex_unboxed.profile_sbpl.is_some());

        let mut quoted_spec = spec;
        quoted_spec.state_dirs = vec![r#"/Users/dev/dir "quoted"\sub"#.into()];
        let quoted_sbpl = generate_sbpl_profile(&quoted_spec).unwrap();
        assert!(quoted_sbpl.contains(r#"/Users/dev/dir \"quoted\"\\sub"#));
    }

    #[test]
    fn rejects_sbpl_nul_newline_traversal_and_empty_paths() {
        let base = SeatbeltProfileSpec {
            session_id: "sess-bad".into(),
            workspace_root: "/Users/dev/repo".into(),
            state_dirs: vec![],
            protected_paths: vec![],
            decide_socket_path: "/Library/Application Support/grdr/run/decide.sock".into(),
            proxy_port: DEFAULT_PROXY_LOOPBACK_PORT,
            deny_elevation_binaries: true,
        };

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
