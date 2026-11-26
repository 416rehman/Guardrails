// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::IdentityError;
use crate::http_security::{
    DEFAULT_HTTP_TIMEOUT_SECS, pinned_client_for_url, read_bounded_response_text,
    validate_endpoint_url, validate_single_segment,
};
use crate::secret_store::{
    BoxFuture, SecretBytes, SecretStore, SecretStoreKind, validate_secret_key,
};

#[derive(Clone)]
pub struct OpenBaoSecretStore {
    http: Client,
    base_url: Url,
    kv_mount: String,
    transit_mount: Option<String>,
    transit_key: Option<String>,
    token: Zeroizing<String>,
    allow_insecure_loopback: bool,
}

#[derive(Debug, Serialize)]
struct KvWriteRequest<'a> {
    data: KvDataPayload<'a>,
}

#[derive(Debug, Serialize)]
struct KvDataPayload<'a> {
    value_b64: &'a str,
}

#[derive(Debug, Deserialize)]
struct KvReadResponse {
    data: Option<KvReadInner>,
}

#[derive(Debug, Deserialize)]
struct KvReadInner {
    data: Option<KvReadData>,
}

#[derive(Debug, Deserialize)]
struct KvReadData {
    value_b64: Option<String>,
}

#[derive(Debug, Serialize)]
struct TransitEncryptRequest<'a> {
    plaintext: &'a str,
}

#[derive(Debug, Deserialize)]
struct TransitEncryptResponse {
    data: Option<TransitCipherData>,
}

#[derive(Debug, Deserialize)]
struct TransitCipherData {
    ciphertext: String,
}

#[derive(Debug, Serialize)]
struct TransitDecryptRequest<'a> {
    ciphertext: &'a str,
}

#[derive(Debug, Deserialize)]
struct TransitDecryptResponse {
    data: Option<TransitPlainData>,
}

#[derive(Debug, Deserialize)]
struct TransitPlainData {
    plaintext: String,
}

impl std::fmt::Debug for OpenBaoSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenBaoSecretStore")
            .field("base_url", &self.base_url.as_str())
            .field("kv_mount", &self.kv_mount)
            .field("transit_key", &self.transit_key)
            .finish_non_exhaustive()
    }
}

impl OpenBaoSecretStore {
    pub fn new(
        base_url: &str,
        kv_mount: impl Into<String>,
        transit_mount: Option<String>,
        transit_key: Option<String>,
        token: impl Into<String>,
        allow_insecure_loopback: bool,
    ) -> Result<Self, IdentityError> {
        let parsed = validate_endpoint_url(base_url, allow_insecure_loopback)?;
        let kv_mount_val = kv_mount.into();
        validate_single_segment("kv_mount", &kv_mount_val)?;
        match (&transit_mount, &transit_key) {
            (Some(tm), Some(tk)) => {
                validate_single_segment("transit_mount", tm)?;
                validate_single_segment("transit_key", tk)?;
            }
            (None, None) => {}
            _ => {
                return Err(IdentityError::SecretStore(
                    "OpenBao requires both transit_mount and transit_key or neither".to_string(),
                ));
            }
        }
        let token_val = Zeroizing::new(token.into());
        if token_val.trim().is_empty() {
            return Err(IdentityError::SecretStore(
                "OpenBao token must be non-empty".to_string(),
            ));
        }

        let http = Client::builder()
            .https_only(!allow_insecure_loopback)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|e| IdentityError::SecretStore(format!("OpenBao client init failed: {e}")))?;
        Ok(Self {
            http,
            base_url: parsed,
            kv_mount: kv_mount_val,
            transit_mount,
            transit_key,
            token: token_val,
            allow_insecure_loopback,
        })
    }

    async fn pinned_client(&self) -> Result<Client, IdentityError> {
        pinned_client_for_url(&self.base_url, &self.http, self.allow_insecure_loopback).await
    }
}

impl SecretStore for OpenBaoSecretStore {
    fn store_kind(&self) -> SecretStoreKind {
        SecretStoreKind::OpenBaoKvTransit
    }

    fn store_secret(&self, key: &str, value: &[u8]) -> BoxFuture<'_, Result<(), IdentityError>> {
        let key_owned = key.to_string();
        let raw_b64 = Zeroizing::new(B64.encode(value));
        Box::pin(async move {
            validate_secret_key(&key_owned)?;
            let stored = self.maybe_transit_encrypt(raw_b64).await?;
            let url = self
                .base_url
                .join(&format!("v1/{}/data/{key_owned}", self.kv_mount))
                .map_err(|e| IdentityError::InvalidHttpEndpoint(e.to_string()))?;
            let client = self.pinned_client().await?;
            let resp = client
                .post(url)
                .header("X-Vault-Token", self.token.as_str())
                .json(&KvWriteRequest {
                    data: KvDataPayload {
                        value_b64: stored.as_str(),
                    },
                })
                .send()
                .await
                .map_err(|e| IdentityError::SecretStore(format!("OpenBao KV write: {e}")))?;
            if !resp.status().is_success() {
                return Err(IdentityError::SecretStore(format!(
                    "OpenBao KV write returned HTTP {}",
                    resp.status()
                )));
            }
            Ok(())
        })
    }

    fn load_secret(&self, key: &str) -> BoxFuture<'_, Result<Option<SecretBytes>, IdentityError>> {
        let key_owned = key.to_string();
        Box::pin(async move {
            validate_secret_key(&key_owned)?;
            let url = self
                .base_url
                .join(&format!("v1/{}/data/{key_owned}", self.kv_mount))
                .map_err(|e| IdentityError::InvalidHttpEndpoint(e.to_string()))?;
            let client = self.pinned_client().await?;
            let resp = client
                .get(url)
                .header("X-Vault-Token", self.token.as_str())
                .send()
                .await
                .map_err(|e| IdentityError::SecretStore(format!("OpenBao KV read: {e}")))?;
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !resp.status().is_success() {
                return Err(IdentityError::SecretStore(format!(
                    "OpenBao KV read returned HTTP {}",
                    resp.status()
                )));
            }
            let raw_text = read_bounded_response_text(resp, "OpenBao KV read").await?;
            let body: KvReadResponse = serde_json::from_str(&raw_text)
                .map_err(|e| IdentityError::SecretStore(format!("OpenBao KV parse: {e}")))?;
            let Some(stored) = body.data.and_then(|d| d.data).and_then(|d| d.value_b64) else {
                return Ok(None);
            };
            let plain_b64 = self.maybe_transit_decrypt(Zeroizing::new(stored)).await?;
            let bytes = B64
                .decode(plain_b64.as_bytes())
                .map_err(|e| IdentityError::SecretStore(format!("invalid secret b64: {e}")))?;
            Ok(Some(Zeroizing::new(bytes)))
        })
    }

    fn delete_secret(&self, key: &str) -> BoxFuture<'_, Result<(), IdentityError>> {
        let key_owned = key.to_string();
        Box::pin(async move {
            validate_secret_key(&key_owned)?;
            let url = self
                .base_url
                .join(&format!("v1/{}/metadata/{key_owned}", self.kv_mount))
                .map_err(|e| IdentityError::InvalidHttpEndpoint(e.to_string()))?;
            let client = self.pinned_client().await?;
            let resp = client
                .delete(url)
                .header("X-Vault-Token", self.token.as_str())
                .send()
                .await
                .map_err(|e| IdentityError::SecretStore(format!("OpenBao delete: {e}")))?;
            if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NOT_FOUND {
                return Err(IdentityError::SecretStore(format!(
                    "OpenBao delete returned HTTP {}",
                    resp.status()
                )));
            }
            Ok(())
        })
    }
}

impl OpenBaoSecretStore {
    async fn maybe_transit_encrypt(
        &self,
        raw_b64: Zeroizing<String>,
    ) -> Result<Zeroizing<String>, IdentityError> {
        let (Some(t_mount), Some(t_key)) = (&self.transit_mount, &self.transit_key) else {
            return Ok(raw_b64);
        };
        let url = self
            .base_url
            .join(&format!("v1/{t_mount}/encrypt/{t_key}"))
            .map_err(|e| IdentityError::InvalidHttpEndpoint(e.to_string()))?;
        let client = self.pinned_client().await?;
        let resp = client
            .post(url)
            .header("X-Vault-Token", self.token.as_str())
            .json(&TransitEncryptRequest {
                plaintext: raw_b64.as_str(),
            })
            .send()
            .await
            .map_err(|e| IdentityError::SecretStore(format!("OpenBao transit encrypt: {e}")))?;
        if !resp.status().is_success() {
            return Err(IdentityError::SecretStore(format!(
                "OpenBao transit encrypt returned HTTP {}",
                resp.status()
            )));
        }
        let raw_text = read_bounded_response_text(resp, "OpenBao transit encrypt").await?;
        let parsed: TransitEncryptResponse = serde_json::from_str(&raw_text).map_err(|e| {
            IdentityError::SecretStore(format!("OpenBao transit parse failed: {e}"))
        })?;
        Ok(Zeroizing::new(
            parsed
                .data
                .ok_or_else(|| IdentityError::SecretStore("missing transit data".into()))?
                .ciphertext,
        ))
    }

    async fn maybe_transit_decrypt(
        &self,
        stored: Zeroizing<String>,
    ) -> Result<Zeroizing<String>, IdentityError> {
        let (Some(t_mount), Some(t_key)) = (&self.transit_mount, &self.transit_key) else {
            return Ok(stored);
        };
        let url = self
            .base_url
            .join(&format!("v1/{t_mount}/decrypt/{t_key}"))
            .map_err(|e| IdentityError::InvalidHttpEndpoint(e.to_string()))?;
        let client = self.pinned_client().await?;
        let resp = client
            .post(url)
            .header("X-Vault-Token", self.token.as_str())
            .json(&TransitDecryptRequest {
                ciphertext: stored.as_str(),
            })
            .send()
            .await
            .map_err(|e| IdentityError::SecretStore(format!("OpenBao transit decrypt: {e}")))?;
        if !resp.status().is_success() {
            return Err(IdentityError::SecretStore(format!(
                "OpenBao transit decrypt returned HTTP {}",
                resp.status()
            )));
        }
        let raw_text = read_bounded_response_text(resp, "OpenBao transit decrypt").await?;
        let parsed: TransitDecryptResponse = serde_json::from_str(&raw_text)
            .map_err(|e| IdentityError::SecretStore(format!("OpenBao decrypt parse: {e}")))?;
        Ok(Zeroizing::new(
            parsed
                .data
                .ok_or_else(|| IdentityError::SecretStore("missing decrypt data".into()))?
                .plaintext,
        ))
    }
}
