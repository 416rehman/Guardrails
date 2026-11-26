// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;

use grdr_model::InstallProfile;
use grdr_wire::endpoint::{
    EndpointOverrides, PlatformKind, resolve_endpoint, validate_unix_endpoint_path,
    validate_windows_pipe_name,
};
use grdr_wire::messages::EndpointServiceKind;
use grdr_wire::peer_auth::Profile;
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
    let wire_os = to_wire_platform(os);
    if ns == "grdr" {
        let wire_profile = match profile {
            InstallProfile::Protected => Profile::Protected,
            InstallProfile::User => Profile::User,
        };
        let wire_service = match kind {
            EndpointKind::Decide => EndpointServiceKind::Decide,
            EndpointKind::Local => EndpointServiceKind::Local,
            EndpointKind::Provider => EndpointServiceKind::Unspecified,
        };
        let mut overrides = EndpointOverrides::default();
        if let Some(dir) = user_runtime_dir {
            let safe = require_safe_user_runtime_dir(Some(dir))?;
            overrides.xdg_runtime_dir = Some(PathBuf::from(safe));
        }
        if let Some(suffix) = session_suffix {
            overrides.windows_user_sid = Some(sanitize_segment(suffix)?);
        }
        let resolved = resolve_endpoint(wire_service, wire_profile, &overrides, wire_os)
            .map_err(|err| IpcError::InvalidAddress(err.to_string()))?;
        let addr = match (resolved.unix_path, resolved.pipe_name) {
            (Some(path), _) => LocalEndpointAddress::UnixSocket { path },
            (_, Some(pipe_name)) => LocalEndpointAddress::WindowsPipe { pipe_name },
            (None, None) => {
                return Err(IpcError::InvalidAddress(
                    "resolved endpoint produced neither socket nor pipe".into(),
                ));
            }
        };
        validate_endpoint_address(os, &addr)?;
        return Ok(addr);
    }

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
            pipe_name: format!(r"\\.\pipe\{ns}-protected-{slug}"),
        },
        (TargetOsKind::Windows, InstallProfile::User) => {
            let raw_suffix = session_suffix.ok_or_else(|| {
                IpcError::InvalidAddress(
                    "Windows User profile requires explicit per-session suffix".into(),
                )
            })?;
            let suffix = sanitize_segment(raw_suffix)?;
            LocalEndpointAddress::WindowsPipe {
                pipe_name: format!(r"\\.\pipe\{ns}-user-{suffix}-{slug}"),
            }
        }
    };
    validate_endpoint_address(os, &addr)?;
    Ok(addr)
}

const fn to_wire_platform(os: TargetOsKind) -> PlatformKind {
    match os {
        TargetOsKind::Linux => PlatformKind::Linux,
        TargetOsKind::MacOs => PlatformKind::MacOs,
        TargetOsKind::Windows => PlatformKind::Windows,
    }
}

pub fn validate_endpoint_address(
    os: TargetOsKind,
    addr: &LocalEndpointAddress,
) -> Result<(), IpcError> {
    match addr {
        LocalEndpointAddress::UnixSocket { path } => {
            validate_unix_endpoint_path(path, to_wire_platform(os))
                .map_err(|err| IpcError::InvalidAddress(err.to_string()))
        }
        LocalEndpointAddress::WindowsPipe { pipe_name } => {
            if let Some(leaf) = pipe_name.strip_prefix(WINDOWS_PIPE_PREFIX)
                && leaf.len() > MAX_PIPE_LEAF_LEN
            {
                return Err(IpcError::InvalidAddress(
                    "Windows named pipe leaf exceeds maximum length".into(),
                ));
            }
            validate_windows_pipe_name(pipe_name)
                .map_err(|err| IpcError::InvalidAddress(err.to_string()))
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
                pipe_name: r"\\.\pipe\grdr-user-S-1-5-21-1001-local".into()
            }
        );
        let tmp_sock = LocalEndpointAddress::UnixSocket {
            path: PathBuf::from("/tmp/grdr-evil.sock"),
        };
        assert!(matches!(
            validate_endpoint_address(TargetOsKind::Linux, &tmp_sock),
            Err(IpcError::InvalidAddress(_))
        ));
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
