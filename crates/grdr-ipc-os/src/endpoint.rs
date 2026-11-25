// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;

use grdr_model::InstallProfile;
use serde::{Deserialize, Serialize};

use crate::IpcError;

pub const MACOS_SUN_PATH_LIMIT: usize = 104;
pub const LINUX_SUN_PATH_LIMIT: usize = 108;
const WINDOWS_PIPE_PREFIX: &str = r"\\.\pipe\";
const MAX_PIPE_LEAF_LEN: usize = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    Decide,
    Local,
    Provider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetOsKind {
    Linux,
    MacOs,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum LocalEndpointAddress {
    UnixSocket { path: PathBuf },
    WindowsPipe { pipe_name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipeImpersonationLevel {
    Identification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipeClientAccessPolicy {
    FiveRightRestrictedMask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsPipeOpenPolicy {
    pub impersonation: PipeImpersonationLevel,
    pub access_policy: PipeClientAccessPolicy,
    pub reject_remote_clients: bool,
}

impl EndpointKind {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Decide => "decide",
            Self::Local => "local",
            Self::Provider => "provider",
        }
    }
}

impl TargetOsKind {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

impl Default for WindowsPipeOpenPolicy {
    fn default() -> Self {
        Self {
            impersonation: PipeImpersonationLevel::Identification,
            access_policy: PipeClientAccessPolicy::FiveRightRestrictedMask,
            reject_remote_clients: true,
        }
    }
}

pub fn resolve_endpoint_address(
    os: TargetOsKind,
    kind: EndpointKind,
    profile: InstallProfile,
    namespace: &str,
    user_runtime_dir: Option<&str>,
    session_suffix: Option<&str>,
) -> Result<LocalEndpointAddress, IpcError> {
    let ns = sanitize_segment(namespace)?;
    let slug = kind.slug();
    let addr = match (os, profile) {
        (TargetOsKind::Linux, InstallProfile::Protected) => LocalEndpointAddress::UnixSocket {
            path: PathBuf::from(format!("/run/{ns}/{slug}.sock")),
        },
        (TargetOsKind::Linux, InstallProfile::User) => {
            let base = require_safe_user_runtime_dir(user_runtime_dir)?;
            LocalEndpointAddress::UnixSocket {
                path: PathBuf::from(format!("{base}/{ns}/{slug}.sock")),
            }
        }
        (TargetOsKind::MacOs, InstallProfile::Protected) => LocalEndpointAddress::UnixSocket {
            path: PathBuf::from(format!("/Library/Application Support/{ns}/run/{slug}.sock")),
        },
        (TargetOsKind::MacOs, InstallProfile::User) => {
            let base = require_safe_user_runtime_dir(user_runtime_dir)?;
            LocalEndpointAddress::UnixSocket {
                path: PathBuf::from(format!("{base}/{ns}/run/{slug}.sock")),
            }
        }
        (TargetOsKind::Windows, InstallProfile::Protected) => LocalEndpointAddress::WindowsPipe {
            pipe_name: format!(r"\\.\pipe\{ns}-{slug}"),
        },
        (TargetOsKind::Windows, InstallProfile::User) => {
            let raw_suffix = session_suffix.ok_or_else(|| {
                IpcError::InvalidAddress(
                    "Windows User profile requires explicit per-session suffix".into(),
                )
            })?;
            let suffix = sanitize_segment(raw_suffix)?;
            LocalEndpointAddress::WindowsPipe {
                pipe_name: format!(r"\\.\pipe\{ns}-{slug}-{suffix}"),
            }
        }
    };
    validate_endpoint_address(os, &addr)?;
    Ok(addr)
}

pub fn validate_endpoint_address(
    os: TargetOsKind,
    addr: &LocalEndpointAddress,
) -> Result<(), IpcError> {
    match addr {
        LocalEndpointAddress::UnixSocket { path } => {
            let raw = path.to_string_lossy();
            if raw.trim().is_empty()
                || !raw.starts_with('/')
                || raw.chars().any(|c| c == '\0' || c.is_control())
            {
                return Err(IpcError::InvalidAddress(format!(
                    "unix socket path `{raw}` must be non-empty, absolute, and control-char free"
                )));
            }
            if raw
                .split('/')
                .skip(1)
                .any(|seg| seg.is_empty() || seg == "." || seg == "..")
            {
                return Err(IpcError::InvalidAddress(format!(
                    "unix socket path `{raw}` contains invalid `.`, `..`, or empty segments"
                )));
            }
            let max_len = match os {
                TargetOsKind::MacOs => MACOS_SUN_PATH_LIMIT,
                _ => LINUX_SUN_PATH_LIMIT,
            };
            if raw.len() >= max_len {
                return Err(IpcError::InvalidAddress(format!(
                    "unix socket path `{raw}` length {} exceeds sun_path limit {}",
                    raw.len(),
                    max_len
                )));
            }
            Ok(())
        }
        LocalEndpointAddress::WindowsPipe { pipe_name } => {
            let Some(leaf) = pipe_name.strip_prefix(WINDOWS_PIPE_PREFIX) else {
                return Err(IpcError::InvalidAddress(format!(
                    "Windows named pipe `{pipe_name}` must start with `\\\\.\\pipe\\`"
                )));
            };
            if leaf.is_empty()
                || leaf.len() > MAX_PIPE_LEAF_LEN
                || leaf.contains("..")
                || leaf.chars().any(|c| {
                    c == '\\' || c == '/' || c == '\0' || c.is_control() || c.is_whitespace()
                })
            {
                return Err(IpcError::InvalidAddress(format!(
                    "Windows named pipe `{pipe_name}` contains invalid leaf characters"
                )));
            }
            Ok(())
        }
    }
}

fn require_safe_user_runtime_dir(dir: Option<&str>) -> Result<&str, IpcError> {
    let raw = dir
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            IpcError::InvalidAddress(
                "Unix User profile requires explicit private runtime directory".into(),
            )
        })?;
    if !raw.starts_with('/') || raw.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(IpcError::InvalidAddress(format!(
            "runtime directory `{raw}` must be absolute and control-char free"
        )));
    }
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .skip(1)
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(IpcError::InvalidAddress(format!(
            "runtime directory `{raw}` contains invalid `.`, `..`, or empty segments"
        )));
    }
    for forbidden in ["/tmp", "/var/tmp", "/private/tmp", "/dev/shm"] {
        if trimmed == forbidden
            || trimmed
                .strip_prefix(forbidden)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return Err(IpcError::InvalidAddress(format!(
                "world-writable directory `{trimmed}` is forbidden for endpoint sockets"
            )));
        }
    }
    Ok(trimmed)
}

fn sanitize_segment(raw: &str) -> Result<String, IpcError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(IpcError::InvalidAddress(format!(
            "invalid endpoint namespace or suffix `{raw}`"
        )));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_platform_endpoints_within_sun_path_and_pipe_rules() {
        let mac = resolve_endpoint_address(
            TargetOsKind::MacOs,
            EndpointKind::Decide,
            InstallProfile::Protected,
            "grdr",
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            mac,
            LocalEndpointAddress::UnixSocket {
                path: PathBuf::from("/Library/Application Support/grdr/run/decide.sock")
            }
        );

        let win = resolve_endpoint_address(
            TargetOsKind::Windows,
            EndpointKind::Local,
            InstallProfile::User,
            "grdr",
            None,
            Some("S-1-5-21-1001"),
        )
        .unwrap();
        assert_eq!(
            win,
            LocalEndpointAddress::WindowsPipe {
                pipe_name: r"\\.\pipe\grdr-local-S-1-5-21-1001".into()
            }
        );
    }

    #[test]
    fn rejects_tmp_fallbacks_missing_suffixes_traversal_and_oversized_paths() {
        assert!(matches!(
            resolve_endpoint_address(
                TargetOsKind::Linux,
                EndpointKind::Decide,
                InstallProfile::User,
                "grdr",
                None,
                None,
            ),
            Err(IpcError::InvalidAddress(_))
        ));
        assert!(matches!(
            resolve_endpoint_address(
                TargetOsKind::Linux,
                EndpointKind::Decide,
                InstallProfile::User,
                "grdr",
                Some("/tmp"),
                None,
            ),
            Err(IpcError::InvalidAddress(_))
        ));
        assert!(matches!(
            resolve_endpoint_address(
                TargetOsKind::Windows,
                EndpointKind::Decide,
                InstallProfile::User,
                "grdr",
                None,
                None,
            ),
            Err(IpcError::InvalidAddress(_))
        ));

        let traversal = LocalEndpointAddress::UnixSocket {
            path: PathBuf::from("/run/grdr/../evil.sock"),
        };
        assert!(matches!(
            validate_endpoint_address(TargetOsKind::Linux, &traversal),
            Err(IpcError::InvalidAddress(_))
        ));

        let pipe_traversal = LocalEndpointAddress::WindowsPipe {
            pipe_name: r"\\.\pipe\grdr\..\evil".into(),
        };
        assert!(matches!(
            validate_endpoint_address(TargetOsKind::Windows, &pipe_traversal),
            Err(IpcError::InvalidAddress(_))
        ));

        let too_long = LocalEndpointAddress::UnixSocket {
            path: PathBuf::from(format!("/{}/decide.sock", "a".repeat(120))),
        };
        assert!(matches!(
            validate_endpoint_address(TargetOsKind::MacOs, &too_long),
            Err(IpcError::InvalidAddress(_))
        ));

        for forbidden_dir in [
            "/tmp/grdr",
            "/var/tmp/sub",
            "/private/tmp/sub",
            "/dev/shm/grdr",
            "relative/dir",
        ] {
            assert!(matches!(
                resolve_endpoint_address(
                    TargetOsKind::Linux,
                    EndpointKind::Decide,
                    InstallProfile::User,
                    "grdr",
                    Some(forbidden_dir),
                    None,
                ),
                Err(IpcError::InvalidAddress(_))
            ));
        }
    }
}
