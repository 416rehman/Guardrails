// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::Arc;

use grdr_crypto::SigningKeypair;
use grdr_integrations::outbox::{
    CircuitBreakerConfig, DeliveryOutcome, ExportEnvelope, ExportStream, OutboxQueue, RetryPolicy,
};
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_proto::common::ErrorClass;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};

use super::limits::rest_limits;
use super::webhook_signing::{
    generate_signing_material, not_found_endpoint, sign_webhook_header, to_public_endpoint,
};
use super::webhook_ssrf::{SignedWebhookHeaders, validate_webhook_url};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WebhookSigningAlg {
    #[default]
    Ed25519,
    HmacSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WebhookEndpointState {
    #[default]
    Active,
    DisabledGone,
    CircuitOpen,
    Paused,
}

#[derive(Clone)]
pub struct SigningMaterial {
    pub alg: WebhookSigningAlg,
    pub ed25519: Option<SigningKeypair>,
    pub hmac_secret: Option<Vec<u8>>,
    pub key_id: String,
    pub expires_at_unix: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct StoredWebhookEndpoint {
    pub id: String,
    pub tenant_id: String,
    pub url: String,
    pub topics: Vec<String>,
    pub signing_algorithm: WebhookSigningAlg,
    pub state: WebhookEndpointState,
    pub primary: SigningMaterial,
    pub previous: Option<SigningMaterial>,
    pub outbox: OutboxQueue,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicWebhookEndpoint {
    pub id: String,
    pub url: String,
    pub topics: Vec<String>,
    pub signing_algorithm: WebhookSigningAlg,
    pub state: WebhookEndpointState,
    pub key_id: String,
    pub public_key_b64: Option<String>,
    pub previous_key_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeFeedEntry {
    pub seq: u64,
    pub id: String,
    pub topic: String,
    pub tenant_id: String,
    pub timestamp: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWebhookEndpointRequest {
    pub url: String,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub signing_algorithm: WebhookSigningAlg,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SendTestWebhookRequest {
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChangeFeedQuery {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct WebhookStore {
    inner: Arc<RwLock<WebhookStoreInner>>,
}

#[derive(Debug, Default)]
struct WebhookStoreInner {
    endpoints: BTreeMap<String, StoredWebhookEndpoint>,
    change_feed: Vec<ChangeFeedEntry>,
    next_seq: u64,
}

impl std::fmt::Debug for SigningMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningMaterial")
            .field("alg", &self.alg)
            .field("has_ed25519", &self.ed25519.is_some())
            .field("has_hmac_secret", &self.hmac_secret.is_some())
            .field("key_id", &self.key_id)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl WebhookStore {
    pub async fn list_endpoints(&self, tenant_id: &str) -> Vec<PublicWebhookEndpoint> {
        self.inner
            .read()
            .await
            .endpoints
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .map(to_public_endpoint)
            .collect()
    }

    pub async fn get_endpoint(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<PublicWebhookEndpoint, ApiError> {
        let guard = self.inner.read().await;
        let ep = guard
            .endpoints
            .get(id)
            .filter(|e| e.tenant_id == tenant_id)
            .ok_or_else(|| not_found_endpoint(id))?;
        Ok(to_public_endpoint(ep))
    }

    pub async fn create_endpoint(
        &self,
        tenant_id: &str,
        req: CreateWebhookEndpointRequest,
    ) -> Result<(PublicWebhookEndpoint, Option<String>), ApiError> {
        validate_webhook_url(&req.url)?;
        let (primary, created_secret) = generate_signing_material(req.signing_algorithm)?;
        let id = format!("wh_{}", Uuid::now_v7().simple());
        let now = Timestamp::now().to_string();
        let topics = if req.topics.is_empty() {
            vec!["finding.opened".into(), "approval.requested".into()]
        } else {
            req.topics
        };
        let ep = StoredWebhookEndpoint {
            id: id.clone(),
            tenant_id: tenant_id.to_owned(),
            url: req.url,
            topics,
            signing_algorithm: req.signing_algorithm,
            state: WebhookEndpointState::Active,
            primary,
            previous: None,
            outbox: OutboxQueue::new(
                id.clone(),
                RetryPolicy::export_delivery_default(),
                CircuitBreakerConfig::default(),
            ),
            created_at: now.clone(),
            updated_at: now,
        };
        let public = to_public_endpoint(&ep);
        let max_endpoints = rest_limits().max_store_items.max(1);
        let mut guard = self.inner.write().await;
        let tenant_count = guard
            .endpoints
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .count();
        if tenant_count >= max_endpoints {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::FailedPrecondition,
                grdr_code: crate::connect_error::CODE_API_BAD_REQUEST.into(),
                reason: "WEBHOOK_LIMIT_EXCEEDED".into(),
                class: ErrorClass::RateLimit,
                message: "Tenant webhook endpoint capacity reached.".into(),
                fix: "Delete unused webhook endpoints before creating more.".into(),
                metadata: BTreeMap::new(),
            }));
        }
        guard.endpoints.insert(id, ep);
        Ok((public, created_secret))
    }

    pub async fn delete_endpoint(&self, tenant_id: &str, id: &str) -> Result<(), ApiError> {
        let mut guard = self.inner.write().await;
        let matches_tenant = guard
            .endpoints
            .get(id)
            .is_some_and(|e| e.tenant_id == tenant_id);
        if !matches_tenant {
            return Err(not_found_endpoint(id));
        }
        guard.endpoints.remove(id);
        Ok(())
    }

    pub async fn rotate_key(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<(PublicWebhookEndpoint, Option<String>), ApiError> {
        let mut guard = self.inner.write().await;
        let ep = guard
            .endpoints
            .get_mut(id)
            .filter(|e| e.tenant_id == tenant_id)
            .ok_or_else(|| not_found_endpoint(id))?;
        let (next_primary, next_secret) = generate_signing_material(ep.signing_algorithm)?;
        let mut old = ep.primary.clone();
        old.expires_at_unix = Some(
            Timestamp::now()
                .as_second()
                .saturating_add(rest_limits().idempotency_ttl_secs),
        );
        ep.previous = Some(old);
        ep.primary = next_primary;
        ep.updated_at = Timestamp::now().to_string();
        Ok((to_public_endpoint(ep), next_secret))
    }

    pub async fn prepare_signed_test_delivery(
        &self,
        tenant_id: &str,
        id: &str,
        req: SendTestWebhookRequest,
    ) -> Result<(String, SignedWebhookHeaders), ApiError> {
        let mut guard = self.inner.write().await;
        let ep = guard
            .endpoints
            .get_mut(id)
            .filter(|e| e.tenant_id == tenant_id)
            .ok_or_else(|| not_found_endpoint(id))?;
        if ep.state == WebhookEndpointState::DisabledGone {
            return Err(ApiError::invalid_argument(
                CODE_INVALID_INPUT,
                "WEBHOOK_DISABLED_GONE",
                "Webhook endpoint was disabled after returning 410 Gone.",
                "Create a new webhook endpoint.",
            ));
        }
        let now = Timestamp::now();
        let ts_unix = now.as_second();
        let msg_id = format!("msg_{}", Uuid::now_v7().simple());
        let topic = req.topic.unwrap_or_else(|| "webhook.test".into());
        let body_val = req.payload.unwrap_or_else(|| {
            json!({
                "id": msg_id,
                "topic": topic,
                "tenantId": tenant_id,
                "test": true,
            })
        });
        let body = serde_json::to_vec(&body_val).unwrap_or_else(|_| b"{}".to_vec());
        let envelope = ExportEnvelope {
            grdr_export: "1.0".into(),
            stream: ExportStream::Events,
            record_id: msg_id.clone(),
            revision: 1,
            dedup_key: msg_id.clone(),
            emitted_at: now,
            organisation: tenant_id.to_owned(),
            replay: false,
            record: body_val,
        };
        let _ = ep.outbox.enqueue(envelope, now);
        let signature = sign_webhook_header(ep, &msg_id, ts_unix, &body);
        Ok((
            ep.url.clone(),
            SignedWebhookHeaders {
                webhook_id: msg_id,
                webhook_timestamp: ts_unix,
                webhook_signature: signature,
                body,
            },
        ))
    }

    pub async fn record_delivery_status(
        &self,
        tenant_id: &str,
        endpoint_id: &str,
        msg_id: &str,
        http_status: Option<u16>,
        err_msg: Option<&str>,
    ) -> Option<WebhookEndpointState> {
        let now = Timestamp::now();
        let mut guard = self.inner.write().await;
        let ep = guard
            .endpoints
            .get_mut(endpoint_id)
            .filter(|e| e.tenant_id == tenant_id)?;
        match http_status {
            Some(code) if (200..300).contains(&code) => {
                let _ = ep
                    .outbox
                    .record_delivery(msg_id, DeliveryOutcome::Success, now);
                ep.state = WebhookEndpointState::Active;
            }
            Some(410) => {
                let _ = ep.outbox.record_delivery(
                    msg_id,
                    DeliveryOutcome::NonRetryableFailure {
                        status_code: 410,
                        reason: "endpoint returned 410 Gone".into(),
                    },
                    now,
                );
                ep.state = WebhookEndpointState::DisabledGone;
            }
            Some(code) => {
                let _ = ep.outbox.record_delivery(
                    msg_id,
                    DeliveryOutcome::RetryableFailure {
                        retry_after_secs: None,
                        reason: format!("HTTP {code}"),
                    },
                    now,
                );
            }
            None => {
                let _ = ep.outbox.record_delivery(
                    msg_id,
                    DeliveryOutcome::RetryableFailure {
                        retry_after_secs: None,
                        reason: err_msg.unwrap_or("transport failure").to_owned(),
                    },
                    now,
                );
            }
        }
        ep.updated_at = now.to_string();
        Some(ep.state)
    }

    pub async fn append_change_event(&self, tenant_id: &str, topic: &str, payload: Value) {
        let max_feed = rest_limits().max_store_items.max(1);
        let mut guard = self.inner.write().await;
        if guard.change_feed.len() >= max_feed {
            let overflow = guard
                .change_feed
                .len()
                .saturating_sub(max_feed)
                .saturating_add(1);
            guard.change_feed.drain(..overflow);
        }
        guard.next_seq = guard.next_seq.saturating_add(1);
        let seq = guard.next_seq;
        guard.change_feed.push(ChangeFeedEntry {
            seq,
            id: format!("chg_evt_{seq}"),
            topic: topic.to_owned(),
            tenant_id: tenant_id.to_owned(),
            timestamp: Timestamp::now().to_string(),
            payload,
        });
    }

    pub async fn read_change_feed(
        &self,
        tenant_id: &str,
        after_seq: u64,
        limit: usize,
    ) -> (Vec<ChangeFeedEntry>, String) {
        let cap = limit.clamp(1, 200);
        let guard = self.inner.read().await;
        let items: Vec<ChangeFeedEntry> = guard
            .change_feed
            .iter()
            .filter(|e| e.tenant_id == tenant_id && e.seq > after_seq)
            .take(cap)
            .cloned()
            .collect();
        let next_cursor = items
            .last()
            .map(|e| e.seq.to_string())
            .unwrap_or_else(|| after_seq.to_string());
        (items, next_cursor)
    }
}
