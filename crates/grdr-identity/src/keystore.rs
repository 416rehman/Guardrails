// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::path::PathBuf;

use grdr_crypto::{constant_time_eq, hmac_sha256_hex};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::IdentityError;
use crate::openbao_store::OpenBaoSecretStore;
use crate::secret_store::{
    BoxFuture, DpapiSecretStore, KeychainSecretStore, LinuxKernelKeyringStore, SecretBytes,
    SecretStore, SecretStoreKind,
};

#[derive(Debug, Clone)]
pub enum OsKeystore {
    Win32Dpapi(DpapiSecretStore),
    MacOsKeychain(KeychainSecretStore),
    LinuxKernelKeyring(LinuxKernelKeyringStore),
    OpenBao(OpenBaoSecretStore),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptedCredentialMetadata {
    pub crd_id: String,
    pub locator_id: String,
    pub store_kind: SecretStoreKind,
    pub adopted_at: Timestamp,
}

impl OsKeystore {
    pub fn open_platform(
        dpapi_root: Option<PathBuf>,
        app_entropy: Vec<u8>,
        service_or_namespace: &str,
    ) -> Result<Self, IdentityError> {
        #[cfg(windows)]
        {
            let _ = service_or_namespace;
            let dir = dpapi_root.ok_or_else(|| {
                IdentityError::SecretStore("Windows DPAPI store requires root_dir".to_string())
            })?;
            Ok(Self::Win32Dpapi(DpapiSecretStore::new(dir, app_entropy)?))
        }
        #[cfg(target_os = "macos")]
        {
            let _ = (dpapi_root, app_entropy);
            Ok(Self::MacOsKeychain(KeychainSecretStore::new(
                service_or_namespace,
            )?))
        }
        #[cfg(target_os = "linux")]
        {
            let _ = (dpapi_root, app_entropy);
            Ok(Self::LinuxKernelKeyring(LinuxKernelKeyringStore::new(
                service_or_namespace,
            )?))
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            let _ = (dpapi_root, app_entropy, service_or_namespace);
            Err(IdentityError::SecretStore(
                "unsupported OS keystore target".to_string(),
            ))
        }
    }
}

impl SecretStore for OsKeystore {
    fn store_kind(&self) -> SecretStoreKind {
        match self {
            Self::Win32Dpapi(s) => s.store_kind(),
            Self::MacOsKeychain(s) => s.store_kind(),
            Self::LinuxKernelKeyring(s) => s.store_kind(),
            Self::OpenBao(s) => s.store_kind(),
        }
    }

    fn store_secret(&self, key: &str, value: &[u8]) -> BoxFuture<'_, Result<(), IdentityError>> {
        match self {
            Self::Win32Dpapi(s) => s.store_secret(key, value),
            Self::MacOsKeychain(s) => s.store_secret(key, value),
            Self::LinuxKernelKeyring(s) => s.store_secret(key, value),
            Self::OpenBao(s) => s.store_secret(key, value),
        }
    }

    fn load_secret(&self, key: &str) -> BoxFuture<'_, Result<Option<SecretBytes>, IdentityError>> {
        match self {
            Self::Win32Dpapi(s) => s.load_secret(key),
            Self::MacOsKeychain(s) => s.load_secret(key),
            Self::LinuxKernelKeyring(s) => s.load_secret(key),
            Self::OpenBao(s) => s.load_secret(key),
        }
    }

    fn delete_secret(&self, key: &str) -> BoxFuture<'_, Result<(), IdentityError>> {
        match self {
            Self::Win32Dpapi(s) => s.delete_secret(key),
            Self::MacOsKeychain(s) => s.delete_secret(key),
            Self::LinuxKernelKeyring(s) => s.delete_secret(key),
            Self::OpenBao(s) => s.delete_secret(key),
        }
    }
}

pub async fn verify_secret_store_port_contract<S: SecretStore>(
    store: &S,
    key: &str,
    sample: &[u8],
) -> Result<(), IdentityError> {
    store.store_secret(key, sample).await?;
    let loaded = store.load_secret(key).await?.ok_or_else(|| {
        IdentityError::SecretStore("stored secret could not be loaded back".to_string())
    })?;
    if !constant_time_eq(loaded.as_slice(), sample) {
        return Err(IdentityError::SecretStore(
            "loaded secret bytes did not match stored bytes".to_string(),
        ));
    }
    store.delete_secret(key).await?;
    if store.load_secret(key).await?.is_some() {
        return Err(IdentityError::SecretStore(
            "deleted secret still visible in SecretStore".to_string(),
        ));
    }
    Ok(())
}

pub async fn adopt_credential_into_store<S: SecretStore>(
    store: &S,
    hmac_key: &[u8],
    locator_id: &str,
    public_part: &str,
    secret_bytes: Zeroizing<Vec<u8>>,
    now: Timestamp,
) -> Result<AdoptedCredentialMetadata, IdentityError> {
    if secret_bytes.is_empty() {
        return Err(IdentityError::SecretStore(
            "cannot adopt empty secret value".to_string(),
        ));
    }
    let digest = hmac_sha256_hex(hmac_key, format!("{locator_id}:{public_part}").as_bytes());
    let crd_id = format!("crd_{}", digest.get(..32).unwrap_or(&digest));
    store.store_secret(&crd_id, secret_bytes.as_slice()).await?;
    Ok(AdoptedCredentialMetadata {
        crd_id,
        locator_id: locator_id.to_owned(),
        store_kind: store.store_kind(),
        adopted_at: now,
    })
}
