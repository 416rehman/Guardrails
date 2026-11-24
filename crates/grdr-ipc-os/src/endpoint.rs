// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;

use grdr_model::InstallProfile;
use serde::{Deserialize, Serialize};

use crate::IpcError;

pub const MACOS_SUN_PATH_LIMIT: usize = 104;
pub const LINUX_SUN_PATH_LIMIT: usize = 108;

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
            let base = user_runtime_dir.unwrap_or("/tmp");
            LocalEndpointAddress::UnixSocket {
                path: PathBuf::from(format!("{base}/{ns}/{slug}.sock")),
            }
        }
        (TargetOsKind::MacOs, InstallProfile::Protected) => LocalEndpointAddress::UnixSocket {
            path: PathBuf::from(format!("/Library/Application Support/{ns}/run/{slug}.sock")),
        },
        (TargetOsKind::MacOs, InstallProfile::User) => {
            let base = user_runtime_dir.unwrap_or("/tmp");
            LocalEndpointAddress::UnixSocket {
                path: PathBuf::from(format!("{base}/{ns}/run/{slug}.sock")),
            }
        }
        (TargetOsKind::Windows, InstallProfile::Protected) => LocalEndpointAddress::WindowsPipe {
            pipe_name: format!(r"\\.\pipe\{ns}-{slug}"),
        },
        (TargetOsKind::Windows, InstallProfile::User) => {
            let suffix = session_suffix
                .map(sanitize_segment)
                .transpose()?
                .unwrap_or_else(|| "user".into());
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
            if raw.trim().is_empty() || !raw.starts_with('/') {
                return Err(IpcError::InvalidAddress(format!(
                    "unix socket path `{raw}` must be non-empty and absolute"
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
            if !pipe_name.starts_with(r"\\.\pipe\") || pipe_name.len() <= 9 {
                return Err(IpcError::InvalidAddress(format!(
                    "Windows named pipe `{pipe_name}` must start with `\\\\.\\pipe\\`"
                )));
            }
            Ok(())
        }
    }
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

        let too_long = LocalEndpointAddress::UnixSocket {
            path: PathBuf::from(format!("/{}/decide.sock", "a".repeat(120))),
        };
        assert!(matches!(
            validate_endpoint_address(TargetOsKind::MacOs, &too_long),
            Err(IpcError::InvalidAddress(_))
        ));
    }
}
