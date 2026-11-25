// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::path::{Component, Path, PathBuf};

use grdr_bus_nats::NatsConfig;
use grdr_model::CodedError;
use grdr_ports::ProfileKind;
use grdr_rel_postgres::PostgresConfig;

pub const CODE_STORE_PROFILE_MISMATCH: &str = "GRDR-STORE-0003";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationalAdapterKind {
    Sqlite,
    Postgres,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusAdapterKind {
    Log,
    NatsJetStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobAdapterKind {
    Filesystem,
    ObjectStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LakeAdapterKind {
    LocalDisk,
    ObjectStorage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileAdapterSet {
    pub relational: RelationalAdapterKind,
    pub bus: BusAdapterKind,
    pub blobs: BlobAdapterKind,
    pub lake: LakeAdapterKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageBackend {
    Memory,
    Disk(PathBuf),
    Ha {
        postgres_dsn: String,
        object_store_dir: PathBuf,
        state_dir: PathBuf,
    },
    Distributed {
        postgres_dsn: String,
        nats_url: String,
        object_store_dir: PathBuf,
        state_dir: PathBuf,
    },
}

impl ProfileAdapterSet {
    pub fn expected_for_profile(profile: ProfileKind) -> Self {
        match profile {
            ProfileKind::Embedded => Self {
                relational: RelationalAdapterKind::Sqlite,
                bus: BusAdapterKind::Log,
                blobs: BlobAdapterKind::Filesystem,
                lake: LakeAdapterKind::LocalDisk,
            },
            ProfileKind::Ha => Self {
                relational: RelationalAdapterKind::Postgres,
                bus: BusAdapterKind::Log,
                blobs: BlobAdapterKind::ObjectStore,
                lake: LakeAdapterKind::ObjectStorage,
            },
            ProfileKind::Distributed => Self {
                relational: RelationalAdapterKind::Postgres,
                bus: BusAdapterKind::NatsJetStream,
                blobs: BlobAdapterKind::ObjectStore,
                lake: LakeAdapterKind::ObjectStorage,
            },
        }
    }

    pub fn for_backend(backend: &StorageBackend) -> Self {
        match backend {
            StorageBackend::Memory | StorageBackend::Disk(_) => {
                Self::expected_for_profile(ProfileKind::Embedded)
            }
            StorageBackend::Ha { .. } => Self::expected_for_profile(ProfileKind::Ha),
            StorageBackend::Distributed { .. } => {
                Self::expected_for_profile(ProfileKind::Distributed)
            }
        }
    }
}

pub fn validate_profile_adapters(
    profile: ProfileKind,
    adapters: &ProfileAdapterSet,
) -> Result<(), CodedError> {
    let expected = ProfileAdapterSet::expected_for_profile(profile);
    if adapters != &expected {
        return Err(CodedError::new(
            CODE_STORE_PROFILE_MISMATCH,
            format!(
                "Profile `{}` requires adapters {:?}, but received {:?}.",
                profile.as_str(),
                expected,
                adapters
            ),
            "Align --profile with matching relational, bus, blob, and lake adapters (P6/D-33).",
        ));
    }
    Ok(())
}

pub fn validate_backend_endpoints(
    profile: ProfileKind,
    backend: &StorageBackend,
) -> Result<(), CodedError> {
    validate_profile_adapters(profile, &ProfileAdapterSet::for_backend(backend))?;
    match backend {
        StorageBackend::Memory | StorageBackend::Disk(_) => Ok(()),
        StorageBackend::Ha {
            postgres_dsn,
            object_store_dir,
            state_dir,
        } => {
            PostgresConfig::parse_dsn(postgres_dsn)?.validate()?;
            validate_separated_dirs(object_store_dir, state_dir, "HA")
        }
        StorageBackend::Distributed {
            postgres_dsn,
            nats_url,
            object_store_dir,
            state_dir,
        } => {
            PostgresConfig::parse_dsn(postgres_dsn)?.validate()?;
            NatsConfig::parse_url(nats_url)?.validate()?;
            validate_separated_dirs(object_store_dir, state_dir, "Distributed")
        }
    }
}

pub(crate) fn resolve_ha_dirs(
    data_dir: Option<PathBuf>,
    object_store_dir: Option<PathBuf>,
    profile_label: &str,
) -> Result<(PathBuf, PathBuf), CodedError> {
    match (object_store_dir, data_dir) {
        (Some(obj), Some(state)) => {
            validate_separated_dirs(&obj, &state, profile_label)?;
            Ok((obj, state))
        }
        (Some(obj), None) => {
            let state = sibling_state_dir(&obj);
            validate_separated_dirs(&obj, &state, profile_label)?;
            Ok((obj, state))
        }
        (None, Some(base)) => Ok((base.join("blobs"), base.join("state"))),
        (None, None) => Err(CodedError::new(
            CODE_STORE_PROFILE_MISMATCH,
            format!("{profile_label} profile requires --object-store-dir or --data-dir."),
            "Provide an object-store directory or bucket path.",
        )),
    }
}

fn sibling_state_dir(object_store_dir: &Path) -> PathBuf {
    let name = object_store_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "grdr".into());
    object_store_dir.with_file_name(format!("{name}-state"))
}

fn normalize_path_for_overlap(path: &Path) -> PathBuf {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut stack: Vec<Component<'_>> = Vec::new();
    for comp in abs.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(stack.last(), Some(Component::Normal(_))) {
                    stack.pop();
                } else {
                    stack.push(comp);
                }
            }
            other => stack.push(other),
        }
    }
    let clean: PathBuf = stack.into_iter().collect();
    let mut probe = clean.as_path();
    let mut tail = Vec::new();
    loop {
        if probe.exists()
            && let Ok(canon) = fs::canonicalize(probe)
        {
            let mut out = canon;
            for seg in tail.into_iter().rev() {
                out.push(seg);
            }
            return out;
        }
        let Some(name) = probe.file_name() else {
            return clean;
        };
        tail.push(name.to_os_string());
        let Some(parent) = probe.parent() else {
            return clean;
        };
        probe = parent;
    }
}

fn validate_separated_dirs(
    object_store_dir: &Path,
    state_dir: &Path,
    profile_label: &str,
) -> Result<(), CodedError> {
    if object_store_dir.as_os_str().is_empty() || state_dir.as_os_str().is_empty() {
        return Err(CodedError::new(
            CODE_STORE_PROFILE_MISMATCH,
            format!("{profile_label} profile requires non-empty object_store_dir and state_dir."),
            "Provide --object-store-dir and --data-dir.",
        ));
    }
    let norm_obj = normalize_path_for_overlap(object_store_dir);
    let norm_state = normalize_path_for_overlap(state_dir);
    if norm_state == norm_obj
        || norm_state.starts_with(&norm_obj)
        || norm_obj.starts_with(&norm_state)
    {
        return Err(CodedError::new(
            CODE_STORE_PROFILE_MISMATCH,
            "State/key directory cannot overlap with object_store_dir.",
            "Keep signing.key and lake.kek in a --data-dir outside --object-store-dir.",
        ));
    }
    Ok(())
}
