// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Endpoint path resolution and root-down `lstat` inode/permission verification.

use std::path::{Component, Path, PathBuf};

use crate::messages::EndpointServiceKind;
use crate::peer_auth::{Evidence, Profile, Refusal};

const MAX_UNIX_PATH_FACTS: usize = 64;
const LINUX_SUN_PATH_LIMIT: usize = 108;
const MACOS_SUN_PATH_LIMIT: usize = 104;
const WINDOWS_PIPE_PREFIX: &str = r"\\.\pipe\";
const MAX_PIPE_LEAF_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformKind {
    Linux,
    MacOs,
    Windows,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSource {
    Activation,
    Override,
    Default,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathNodeKind {
    Directory,
    Socket,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EndpointOverrides {
    pub activation_unix_path: Option<PathBuf>,
    pub activation_pipe_name: Option<String>,
    pub env_override_unix_path: Option<PathBuf>,
    pub env_override_pipe_name: Option<String>,
    pub home_dir: Option<PathBuf>,
    pub xdg_runtime_dir: Option<PathBuf>,
    pub local_app_data: Option<PathBuf>,
    pub windows_user_sid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    pub service: EndpointServiceKind,
    pub profile: Profile,
    pub source: AddressSource,
    pub unix_path: Option<PathBuf>,
    pub pipe_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathComponentFact {
    pub path: String,
    pub is_leaf: bool,
    pub node_kind: PathNodeKind,
    pub owner_uid: u32,
    pub gid: u32,
    pub posix_mode: u32,
    pub dev: u64,
    pub ino: u64,
    pub post_dev: u64,
    pub post_ino: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathExpectation {
    pub profile: Profile,
    pub trusted_owner_uids: Vec<u32>,
    pub trusted_group_gids: Vec<u32>,
    pub allow_world_writable_socket_leaf: bool,
}

pub fn resolve_endpoint(
    service: EndpointServiceKind,
    profile: Profile,
    overrides: &EndpointOverrides,
    platform: PlatformKind,
) -> Result<ResolvedEndpoint, Refusal> {
    if profile == Profile::Protected
        && (overrides.env_override_unix_path.is_some()
            || overrides.env_override_pipe_name.is_some())
    {
        return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
            profile,
            detail: "environment endpoint overrides are prohibited in Protected profile"
                .to_string(),
        }));
    }

    if let Some(path) = &overrides.activation_unix_path {
        validate_unix_endpoint_path(path, platform)?;
        return Ok(ResolvedEndpoint {
            service,
            profile,
            source: AddressSource::Activation,
            unix_path: Some(path.clone()),
            pipe_name: None,
        });
    }
    if let Some(pipe) = &overrides.activation_pipe_name {
        validate_windows_pipe_name(pipe)?;
        return Ok(ResolvedEndpoint {
            service,
            profile,
            source: AddressSource::Activation,
            unix_path: None,
            pipe_name: Some(pipe.clone()),
        });
    }
    if let Some(path) = &overrides.env_override_unix_path {
        validate_unix_endpoint_path(path, platform)?;
        return Ok(ResolvedEndpoint {
            service,
            profile,
            source: AddressSource::Override,
            unix_path: Some(path.clone()),
            pipe_name: None,
        });
    }
    if let Some(pipe) = &overrides.env_override_pipe_name {
        validate_windows_pipe_name(pipe)?;
        return Ok(ResolvedEndpoint {
            service,
            profile,
            source: AddressSource::Override,
            unix_path: None,
            pipe_name: Some(pipe.clone()),
        });
    }

    let suffix = service_socket_suffix(service);
    if matches!(platform, PlatformKind::Windows) {
        let pipe = resolve_windows_pipe_name(service, profile, overrides)?;
        validate_windows_pipe_name(&pipe)?;
        return Ok(ResolvedEndpoint {
            service,
            profile,
            source: AddressSource::Default,
            unix_path: None,
            pipe_name: Some(pipe),
        });
    }

    let unix_path = match (profile, platform) {
        (Profile::Protected, PlatformKind::Linux) => PathBuf::from("/run/guardrails").join(suffix),
        (Profile::Protected, PlatformKind::MacOs) => {
            PathBuf::from("/Library/Application Support/grdr/run").join(suffix)
        }
        (Profile::User | Profile::Inherited, _) => {
            if let Some(runtime) = &overrides.xdg_runtime_dir {
                runtime.join("guardrails").join(suffix)
            } else if let Some(home) = &overrides.home_dir {
                home.join(".local/state/guardrails").join(suffix)
            } else {
                return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                    path: String::new(),
                    detail: "User profile requires xdg_runtime_dir or home_dir".to_string(),
                }));
            }
        }
        (Profile::Protected, PlatformKind::Windows) => unreachable_windows_unix_branch(suffix)?,
    };
    validate_unix_endpoint_path(&unix_path, platform)?;
    Ok(ResolvedEndpoint {
        service,
        profile,
        source: AddressSource::Default,
        unix_path: Some(unix_path),
        pipe_name: None,
    })
}

fn unreachable_windows_unix_branch(suffix: &str) -> Result<PathBuf, Refusal> {
    let _ = suffix;
    Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
        profile: Profile::Protected,
        detail: "Windows platform cannot resolve unix socket path".to_string(),
    }))
}

const fn service_socket_suffix(service: EndpointServiceKind) -> &'static str {
    match service {
        EndpointServiceKind::Decide => "decide.sock",
        EndpointServiceKind::Local => "local.sock",
        EndpointServiceKind::ProviderEngine => "provider-engine.sock",
        EndpointServiceKind::ProviderUplink => "provider-uplink.sock",
        EndpointServiceKind::ProviderUpdater => "provider-updater.sock",
        EndpointServiceKind::Unspecified => "grdr.sock",
    }
}

const fn service_pipe_slug(service: EndpointServiceKind) -> &'static str {
    match service {
        EndpointServiceKind::Decide => "decide",
        EndpointServiceKind::Local => "local",
        EndpointServiceKind::ProviderEngine => "provider-engine",
        EndpointServiceKind::ProviderUplink => "provider-uplink",
        EndpointServiceKind::ProviderUpdater => "provider-updater",
        EndpointServiceKind::Unspecified => "grdr",
    }
}

fn resolve_windows_pipe_name(
    service: EndpointServiceKind,
    profile: Profile,
    overrides: &EndpointOverrides,
) -> Result<String, Refusal> {
    let slug = service_pipe_slug(service);
    match profile {
        Profile::Protected => Ok(format!("{WINDOWS_PIPE_PREFIX}grdr-protected-{slug}")),
        Profile::User | Profile::Inherited => {
            let raw_sid = overrides.windows_user_sid.as_deref().ok_or_else(|| {
                Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                    path: String::new(),
                    detail: "Windows User endpoint requires explicit per-user SID".to_string(),
                })
            })?;
            let sid = sanitize_pipe_segment(raw_sid)?;
            Ok(format!("{WINDOWS_PIPE_PREFIX}grdr-user-{sid}-{slug}"))
        }
    }
}

pub fn sanitize_pipe_segment(raw: &str) -> Result<String, Refusal> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 96
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: String::new(),
            detail: "invalid pipe identifier segment".to_string(),
        }));
    }
    Ok(trimmed.to_string())
}

pub fn validate_windows_pipe_name(pipe_name: &str) -> Result<(), Refusal> {
    let Some(leaf) = pipe_name.strip_prefix(WINDOWS_PIPE_PREFIX) else {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: String::new(),
            detail: "Windows pipe must use local \\\\.\\pipe\\ namespace".to_string(),
        }));
    };
    if leaf.is_empty()
        || leaf.len() > MAX_PIPE_LEAF_LEN
        || leaf.contains("..")
        || leaf
            .chars()
            .any(|c| c == '\\' || c == '/' || c == '\0' || c.is_control() || c.is_whitespace())
    {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: String::new(),
            detail: "Windows pipe leaf contains forbidden characters".to_string(),
        }));
    }
    Ok(())
}

pub fn validate_unix_endpoint_path(path: &Path, platform: PlatformKind) -> Result<(), Refusal> {
    let raw = path.to_string_lossy();
    if raw.trim().is_empty()
        || !raw.starts_with('/')
        || raw.chars().any(|c| c == '\0' || c.is_control())
    {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: raw.into_owned(),
            detail: "unix endpoint path must be absolute and control-char free".to_string(),
        }));
    }
    for comp in path.components() {
        if matches!(comp, Component::CurDir | Component::ParentDir) {
            return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                path: raw.into_owned(),
                detail: "unix endpoint path cannot contain `.` or `..`".to_string(),
            }));
        }
    }
    if raw
        .split('/')
        .skip(1)
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: raw.into_owned(),
            detail: "unix endpoint path contains empty or traversal segments".to_string(),
        }));
    }
    for prefix in ["/tmp", "/var/tmp", "/private/tmp", "/dev/shm"] {
        if raw == prefix
            || raw
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                path: raw.into_owned(),
                detail: "world-writable temporary prefix is prohibited for endpoint sockets"
                    .to_string(),
            }));
        }
    }
    let max_len = match platform {
        PlatformKind::MacOs => MACOS_SUN_PATH_LIMIT,
        _ => LINUX_SUN_PATH_LIMIT,
    };
    if raw.len() >= max_len {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: raw.into_owned(),
            detail: format!("unix endpoint path exceeds sun_path limit {max_len}"),
        }));
    }
    Ok(())
}

pub fn check_path(
    facts: &[PathComponentFact],
    expectation: &PathExpectation,
) -> Result<(), Refusal> {
    check_path_chain(facts, expectation, true)
}

pub fn check_directory_path(
    facts: &[PathComponentFact],
    expectation: &PathExpectation,
) -> Result<(), Refusal> {
    check_path_chain(facts, expectation, false)
}

fn check_path_chain(
    facts: &[PathComponentFact],
    expectation: &PathExpectation,
    require_socket_leaf: bool,
) -> Result<(), Refusal> {
    if facts.is_empty() || facts.len() > MAX_UNIX_PATH_FACTS {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: String::new(),
            detail: "invalid ancestor fact chain length".to_string(),
        }));
    }
    let Some(first) = facts.first() else {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: String::new(),
            detail: "missing root component".to_string(),
        }));
    };
    if first.path != "/" || first.is_leaf {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: first.path.clone(),
            detail: "path chain must begin at non-leaf root `/`".to_string(),
        }));
    }

    for (idx, fact) in facts.iter().enumerate() {
        let expect_leaf = require_socket_leaf && idx == facts.len().saturating_sub(1);
        if fact.is_leaf != expect_leaf {
            return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                path: fact.path.clone(),
                detail: "leaf flag allowed only on terminal component".to_string(),
            }));
        }
        if idx > 0
            && let Some(prev) = facts.get(idx.saturating_sub(1))
        {
            verify_contiguous_child(&prev.path, &fact.path)?;
        }
        if fact.node_kind == PathNodeKind::Symlink {
            return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                path: fact.path.clone(),
                detail: "symlink prohibited in endpoint path".to_string(),
            }));
        }
        if fact.dev != fact.post_dev || fact.ino != fact.post_ino {
            return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                path: fact.path.clone(),
                detail: "inode changed across open/check race".to_string(),
            }));
        }
        if expectation.profile == Profile::Protected {
            if fact.owner_uid != 0 {
                return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                    path: fact.path.clone(),
                    detail: "Protected profile requires root-owned endpoint hierarchy".to_string(),
                }));
            }
        } else if !expectation.trusted_owner_uids.contains(&fact.owner_uid) {
            return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                path: fact.path.clone(),
                detail: "untrusted component owner uid".to_string(),
            }));
        }

        if fact.is_leaf {
            if fact.node_kind != PathNodeKind::Socket {
                return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                    path: fact.path.clone(),
                    detail: "leaf endpoint must be a unix domain socket".to_string(),
                }));
            }
            let world_writable = (fact.posix_mode & 0o002) != 0;
            if world_writable && !expectation.allow_world_writable_socket_leaf {
                return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                    path: fact.path.clone(),
                    detail: "socket leaf must not be world-writable".to_string(),
                }));
            }
            let group_writable = (fact.posix_mode & 0o020) != 0;
            if group_writable
                && !expectation.allow_world_writable_socket_leaf
                && !expectation.trusted_group_gids.contains(&fact.gid)
            {
                return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                    path: fact.path.clone(),
                    detail: "socket leaf group-writable for untrusted gid".to_string(),
                }));
            }
        } else {
            if fact.node_kind != PathNodeKind::Directory {
                return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                    path: fact.path.clone(),
                    detail: "non-leaf component must be directory".to_string(),
                }));
            }
            let world_writable = (fact.posix_mode & 0o002) != 0;
            if world_writable {
                return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                    path: fact.path.clone(),
                    detail: "ancestor directory must never be world-writable".to_string(),
                }));
            }
            let group_writable = (fact.posix_mode & 0o020) != 0;
            let trusted_gid = if expectation.profile == Profile::Protected {
                fact.gid == 0
            } else {
                expectation.trusted_group_gids.contains(&fact.gid)
            };
            if group_writable && !trusted_gid {
                return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
                    path: fact.path.clone(),
                    detail: "group-writable ancestor gid not trusted".to_string(),
                }));
            }
        }
    }
    Ok(())
}

fn verify_contiguous_child(parent: &str, child: &str) -> Result<(), Refusal> {
    let prefix = parent.trim_end_matches('/');
    let expected_start = if prefix.is_empty() { "/" } else { prefix };
    let rest = if expected_start == "/" {
        child.strip_prefix('/')
    } else {
        child
            .strip_prefix(expected_start)
            .and_then(|s| s.strip_prefix('/'))
    };
    let Some(segment) = rest else {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: child.to_string(),
            detail: "path component chain is non-contiguous".to_string(),
        }));
    };
    if segment.is_empty() || segment == "." || segment == ".." || segment.contains('/') {
        return Err(Refusal::UnsafeEndpointPath(Evidence::PathUnsafe {
            path: child.to_string(),
            detail: "path chain step must be a single clean child segment".to_string(),
        }));
    }
    Ok(())
}
