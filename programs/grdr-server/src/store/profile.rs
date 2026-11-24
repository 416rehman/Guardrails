// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;

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
    },
    Distributed {
        postgres_dsn: String,
        nats_url: String,
        object_store_dir: PathBuf,
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
        } => {
            PostgresConfig::parse_dsn(postgres_dsn)?.validate()?;
            if object_store_dir.as_os_str().is_empty() {
                return Err(CodedError::new(
                    CODE_STORE_PROFILE_MISMATCH,
                    "HA profile requires a non-empty --object-store-dir.",
                    "Provide --object-store-dir or GRDR_OBJECT_STORE_DIR.",
                ));
            }
            Ok(())
        }
        StorageBackend::Distributed {
            postgres_dsn,
            nats_url,
            object_store_dir,
        } => {
            PostgresConfig::parse_dsn(postgres_dsn)?.validate()?;
            NatsConfig::parse_url(nats_url)?.validate()?;
            if object_store_dir.as_os_str().is_empty() {
                return Err(CodedError::new(
                    CODE_STORE_PROFILE_MISMATCH,
                    "Distributed profile requires a non-empty --object-store-dir.",
                    "Provide --object-store-dir or GRDR_OBJECT_STORE_DIR.",
                ));
            }
            Ok(())
        }
    }
}
