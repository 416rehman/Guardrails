// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use base64::Engine as _;
#[cfg(target_os = "macos")]
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::IdentityError;

pub type SecretBytes = Zeroizing<Vec<u8>>;
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStoreKind {
    Win32Dpapi,
    MacOsKeychain,
    LinuxKernelKeyring,
    OpenBaoKvTransit,
}

pub trait SecretStore: Send + Sync {
    fn store_kind(&self) -> SecretStoreKind;
    fn store_secret(&self, key: &str, value: &[u8]) -> BoxFuture<'_, Result<(), IdentityError>>;
    fn load_secret(&self, key: &str) -> BoxFuture<'_, Result<Option<SecretBytes>, IdentityError>>;
    fn delete_secret(&self, key: &str) -> BoxFuture<'_, Result<(), IdentityError>>;
}

#[derive(Clone)]
pub struct DpapiSecretStore {
    root_dir: PathBuf,
    app_entropy: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct KeychainSecretStore {
    service_name: String,
}

#[derive(Debug, Clone)]
pub struct LinuxKernelKeyringStore {
    namespace: String,
    serials: Arc<Mutex<std::collections::BTreeMap<String, i32>>>,
}

impl std::fmt::Debug for DpapiSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpapiSecretStore")
            .field("root_dir", &self.root_dir)
            .finish_non_exhaustive()
    }
}

impl DpapiSecretStore {
    pub fn new(root_dir: impl Into<PathBuf>, app_entropy: Vec<u8>) -> Result<Self, IdentityError> {
        let dir = root_dir.into();
        #[cfg(windows)]
        crate::dpapi_fs::ensure_real_vault_dir(&dir)?;
        #[cfg(not(windows))]
        {
            if !dir.exists() {
                std::fs::create_dir_all(&dir).map_err(|e| {
                    IdentityError::SecretStore(format!("cannot create DPAPI vault dir: {e}"))
                })?;
            }
            let meta = std::fs::symlink_metadata(&dir).map_err(|e| {
                IdentityError::SecretStore(format!("cannot stat DPAPI vault dir: {e}"))
            })?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(IdentityError::SecretStore(
                    "DPAPI vault root must be a real directory".to_string(),
                ));
            }
        }
        Ok(Self {
            root_dir: dir,
            app_entropy: Zeroizing::new(app_entropy),
        })
    }

    fn key_file(&self, key: &str) -> Result<PathBuf, IdentityError> {
        validate_secret_key(key)?;
        Ok(self.root_dir.join(format!("{key}.dpapi")))
    }

    fn scoped_entropy(&self, key: &str) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            self.app_entropy
                .len()
                .saturating_add(1)
                .saturating_add(key.len()),
        ));
        out.extend_from_slice(&self.app_entropy);
        out.push(0);
        out.extend_from_slice(key.as_bytes());
        out
    }
}

impl SecretStore for DpapiSecretStore {
    fn store_kind(&self) -> SecretStoreKind {
        SecretStoreKind::Win32Dpapi
    }

    fn store_secret(&self, key: &str, value: &[u8]) -> BoxFuture<'_, Result<(), IdentityError>> {
        let path_res = self.key_file(key);
        let root = self.root_dir.clone();
        let entropy = self.scoped_entropy(key);
        let data = Zeroizing::new(value.to_vec());
        Box::pin(async move {
            let path = path_res?;
            #[cfg(windows)]
            {
                let sealed = crate::dpapi::protect_bytes(&data, &entropy)?;
                crate::dpapi_fs::write_dpapi_file_secure(&root, &path, &sealed)
            }
            #[cfg(not(windows))]
            {
                let _ = (root, path, entropy, data);
                Err(IdentityError::SecretStore(
                    "Win32 DPAPI secret store requires Windows host".to_string(),
                ))
            }
        })
    }

    fn load_secret(&self, key: &str) -> BoxFuture<'_, Result<Option<SecretBytes>, IdentityError>> {
        let path_res = self.key_file(key);
        let root = self.root_dir.clone();
        let entropy = self.scoped_entropy(key);
        Box::pin(async move {
            let path = path_res?;
            #[cfg(windows)]
            {
                let Some(sealed) = crate::dpapi_fs::read_dpapi_file_secure(&root, &path)? else {
                    return Ok(None);
                };
                let plain = crate::dpapi::unprotect_bytes(&sealed, &entropy)?;
                Ok(Some(plain))
            }
            #[cfg(not(windows))]
            {
                let _ = (root, path, entropy);
                Err(IdentityError::SecretStore(
                    "Win32 DPAPI secret store requires Windows host".to_string(),
                ))
            }
        })
    }

    fn delete_secret(&self, key: &str) -> BoxFuture<'_, Result<(), IdentityError>> {
        let path_res = self.key_file(key);
        let root = self.root_dir.clone();
        Box::pin(async move {
            let path = path_res?;
            #[cfg(windows)]
            {
                crate::dpapi_fs::delete_dpapi_file_secure(&root, &path)
            }
            #[cfg(not(windows))]
            {
                let _ = (root, path);
                Err(IdentityError::SecretStore(
                    "Win32 DPAPI secret store requires Windows host".to_string(),
                ))
            }
        })
    }
}

impl KeychainSecretStore {
    pub fn new(service_name: impl Into<String>) -> Result<Self, IdentityError> {
        let svc = service_name.into();
        validate_secret_key(&svc)?;
        Ok(Self { service_name: svc })
    }
}

impl SecretStore for KeychainSecretStore {
    fn store_kind(&self) -> SecretStoreKind {
        SecretStoreKind::MacOsKeychain
    }

    fn store_secret(&self, key: &str, value: &[u8]) -> BoxFuture<'_, Result<(), IdentityError>> {
        let key_owned = key.to_string();
        #[cfg(target_os = "macos")]
        let val_b64 = Zeroizing::new(B64.encode(value));
        #[cfg(not(target_os = "macos"))]
        let val_raw = Zeroizing::new(value.to_vec());
        let svc = self.service_name.clone();
        Box::pin(async move {
            validate_secret_key(&key_owned)?;
            validate_secret_key(&svc)?;
            #[cfg(target_os = "macos")]
            {
                let val_hex = Zeroizing::new(encode_hex_bytes(val_b64.as_bytes()));
                let script = Zeroizing::new(format!(
                    "add-generic-password -U -a \"{key_owned}\" -s \"{svc}\" -X \"{}\"\n",
                    val_hex.as_str()
                ));
                run_security_interactive(&script)
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (svc, val_raw);
                Err(IdentityError::SecretStore(
                    "macOS Keychain secret store requires macOS host".to_string(),
                ))
            }
        })
    }

    fn load_secret(&self, key: &str) -> BoxFuture<'_, Result<Option<SecretBytes>, IdentityError>> {
        let key_owned = key.to_string();
        let svc = self.service_name.clone();
        Box::pin(async move {
            validate_secret_key(&key_owned)?;
            validate_secret_key(&svc)?;
            #[cfg(target_os = "macos")]
            {
                let output = std::process::Command::new("/usr/bin/security")
                    .args(["find-generic-password", "-a", &key_owned, "-s", &svc, "-w"])
                    .output()
                    .map_err(|e| {
                        IdentityError::SecretStore(format!("Keychain lookup failed: {e}"))
                    })?;
                if !output.status.success() {
                    if output.status.code() == Some(44) {
                        return Ok(None);
                    }
                    return Err(IdentityError::SecretStore(format!(
                        "Keychain lookup failed with status {:?}",
                        output.status.code()
                    )));
                }
                let raw = Zeroizing::new(output.stdout);
                let text = std::str::from_utf8(raw.as_slice()).map_err(|_| {
                    IdentityError::SecretStore("Keychain output is not valid UTF-8".to_string())
                })?;
                let decoded = B64
                    .decode(text.trim_end_matches(['\r', '\n']))
                    .map_err(|e| {
                        IdentityError::SecretStore(format!("Keychain payload decode failed: {e}"))
                    })?;
                Ok(Some(Zeroizing::new(decoded)))
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = svc;
                Err(IdentityError::SecretStore(
                    "macOS Keychain secret store requires macOS host".to_string(),
                ))
            }
        })
    }

    fn delete_secret(&self, key: &str) -> BoxFuture<'_, Result<(), IdentityError>> {
        let key_owned = key.to_string();
        let svc = self.service_name.clone();
        Box::pin(async move {
            validate_secret_key(&key_owned)?;
            validate_secret_key(&svc)?;
            #[cfg(target_os = "macos")]
            {
                let output = std::process::Command::new("/usr/bin/security")
                    .args(["delete-generic-password", "-a", &key_owned, "-s", &svc])
                    .output()
                    .map_err(|e| {
                        IdentityError::SecretStore(format!("Keychain delete failed: {e}"))
                    })?;
                if !output.status.success() && output.status.code() != Some(44) {
                    return Err(IdentityError::SecretStore(format!(
                        "Keychain delete failed with status {:?}",
                        output.status.code()
                    )));
                }
                Ok(())
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = svc;
                Err(IdentityError::SecretStore(
                    "macOS Keychain secret store requires macOS host".to_string(),
                ))
            }
        })
    }
}

impl LinuxKernelKeyringStore {
    pub fn new(namespace: impl Into<String>) -> Result<Self, IdentityError> {
        let ns = namespace.into();
        validate_keyring_namespace(&ns)?;
        Ok(Self {
            namespace: ns,
            serials: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        })
    }

    fn keyring_desc(&self, key: &str) -> Result<String, IdentityError> {
        validate_secret_key(key)?;
        validate_keyring_namespace(&self.namespace)?;
        Ok(format!("{}:{key}", self.namespace))
    }
}

impl SecretStore for LinuxKernelKeyringStore {
    fn store_kind(&self) -> SecretStoreKind {
        SecretStoreKind::LinuxKernelKeyring
    }

    fn store_secret(&self, key: &str, value: &[u8]) -> BoxFuture<'_, Result<(), IdentityError>> {
        let desc_res = self.keyring_desc(key);
        let payload = Zeroizing::new(value.to_vec());
        let serials = Arc::clone(&self.serials);
        Box::pin(async move {
            let desc = desc_res?;
            #[cfg(target_os = "linux")]
            {
                let serial = crate::linux_keyring::add_user_key(&desc, &payload)?;
                if let Ok(mut guard) = serials.lock() {
                    guard.insert(desc, serial);
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (desc, payload, serials);
                Err(IdentityError::SecretStore(
                    "Linux kernel keyring store requires Linux host".to_string(),
                ))
            }
        })
    }

    fn load_secret(&self, key: &str) -> BoxFuture<'_, Result<Option<SecretBytes>, IdentityError>> {
        let desc_res = self.keyring_desc(key);
        Box::pin(async move {
            let desc = desc_res?;
            #[cfg(target_os = "linux")]
            {
                crate::linux_keyring::request_user_key(&desc)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = desc;
                Err(IdentityError::SecretStore(
                    "Linux kernel keyring store requires Linux host".to_string(),
                ))
            }
        })
    }

    fn delete_secret(&self, key: &str) -> BoxFuture<'_, Result<(), IdentityError>> {
        let desc_res = self.keyring_desc(key);
        let serials = Arc::clone(&self.serials);
        Box::pin(async move {
            let desc = desc_res?;
            #[cfg(target_os = "linux")]
            {
                let cached = serials.lock().ok().and_then(|mut g| g.remove(&desc));
                let maybe_serial = match cached {
                    Some(s) => Some(s),
                    None => crate::linux_keyring::lookup_user_key_serial(&desc)?,
                };
                if let Some(serial) = maybe_serial {
                    crate::linux_keyring::revoke_user_key(serial)?;
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (desc, serials);
                Err(IdentityError::SecretStore(
                    "Linux kernel keyring store requires Linux host".to_string(),
                ))
            }
        })
    }
}

pub(crate) fn validate_secret_key(key: &str) -> Result<(), IdentityError> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        || key.contains("..")
    {
        return Err(IdentityError::SecretStore(
            "invalid secret key identifier".to_string(),
        ));
    }
    Ok(())
}

fn validate_keyring_namespace(ns: &str) -> Result<(), IdentityError> {
    if ns.is_empty()
        || ns.len() > 64
        || !ns
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        || ns.contains("..")
    {
        return Err(IdentityError::SecretStore(
            "invalid Linux keyring namespace".to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn encode_hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(target_os = "macos")]
fn run_security_interactive(stdin_script: &Zeroizing<String>) -> Result<(), IdentityError> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("/usr/bin/security")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| IdentityError::SecretStore(format!("spawning security -i failed: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_script.as_bytes()).map_err(|e| {
            IdentityError::SecretStore(format!("writing security -i stdin failed: {e}"))
        })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| IdentityError::SecretStore(format!("waiting for security -i failed: {e}")))?;
    if !output.status.success() {
        return Err(IdentityError::SecretStore(
            "macOS Keychain command returned non-zero status".to_string(),
        ));
    }
    Ok(())
}
