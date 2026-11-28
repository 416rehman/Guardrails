// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};
use grdr_proto::common::ErrorClass;

use super::super::gitops::api_error_json_response;
use super::authz::{ActorRule, AssuranceRule, PlaneRule, RestPolicy, authorize_rest};
use super::limits::rest_limits;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedResource {
    pub id: String,
    pub collection: String,
    pub tenant_id: String,
    pub data: Map<String, Value>,
    pub created_at: String,
    pub updated_at: String,
}

type TenantCollectionsMap = BTreeMap<(String, String), BTreeMap<String, ManagedResource>>;

#[derive(Debug, Clone, Default)]
pub struct ResourceCatalogStore {
    collections: Arc<RwLock<TenantCollectionsMap>>,
}

impl ResourceCatalogStore {
    pub async fn list(&self, tenant_id: &str, collection: &str) -> Vec<Value> {
        let guard = self.collections.read().await;
        let Some(items) = guard.get(&(tenant_id.to_owned(), collection.to_owned())) else {
            return Vec::new();
        };
        items.values().map(resource_to_json).collect()
    }

    pub async fn get(&self, tenant_id: &str, collection: &str, id: &str) -> Option<Value> {
        let guard = self.collections.read().await;
        guard
            .get(&(tenant_id.to_owned(), collection.to_owned()))
            .and_then(|m| m.get(id))
            .map(resource_to_json)
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        collection: &str,
        mut data: Map<String, Value>,
    ) -> Result<Value, ApiError> {
        let id = data
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("res_{}", Uuid::now_v7().simple()));
        data.remove("id");
        redact_map(&mut data);
        let now = Timestamp::now().to_string();
        let entry = ManagedResource {
            id: id.clone(),
            collection: collection.to_owned(),
            tenant_id: tenant_id.to_owned(),
            data,
            created_at: now.clone(),
            updated_at: now,
        };
        let out = resource_to_json(&entry);
        let max_items = rest_limits().max_store_items.max(1);
        let mut guard = self.collections.write().await;
        let tenant_total: usize = guard
            .iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, m)| m.len())
            .sum();
        let coll = guard
            .entry((tenant_id.to_owned(), collection.to_owned()))
            .or_default();
        if !coll.contains_key(&id) && tenant_total >= max_items {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::FailedPrecondition,
                grdr_code: crate::connect_error::CODE_API_BAD_REQUEST.into(),
                reason: "RESOURCE_LIMIT_EXCEEDED".into(),
                class: ErrorClass::RateLimit,
                message: "Tenant managed resource catalog capacity exceeded.".into(),
                fix: "Delete unused resources before creating additional entries.".into(),
                metadata: BTreeMap::new(),
            }));
        }
        coll.insert(id, entry);
        Ok(out)
    }

    pub async fn upsert(
        &self,
        tenant_id: &str,
        collection: &str,
        id: &str,
        mut data: Map<String, Value>,
    ) -> Result<Value, ApiError> {
        data.remove("id");
        redact_map(&mut data);
        let now = Timestamp::now().to_string();
        let max_items = rest_limits().max_store_items.max(1);
        let mut guard = self.collections.write().await;
        let tenant_total: usize = guard
            .iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, m)| m.len())
            .sum();
        let coll = guard
            .entry((tenant_id.to_owned(), collection.to_owned()))
            .or_default();
        if !coll.contains_key(id) && tenant_total >= max_items {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::FailedPrecondition,
                grdr_code: crate::connect_error::CODE_API_BAD_REQUEST.into(),
                reason: "RESOURCE_LIMIT_EXCEEDED".into(),
                class: ErrorClass::RateLimit,
                message: "Tenant managed resource catalog capacity exceeded.".into(),
                fix: "Delete unused resources before creating additional entries.".into(),
                metadata: BTreeMap::new(),
            }));
        }
        let created_at = coll
            .get(id)
            .map(|r| r.created_at.clone())
            .unwrap_or_else(|| now.clone());
        let entry = ManagedResource {
            id: id.to_owned(),
            collection: collection.to_owned(),
            tenant_id: tenant_id.to_owned(),
            data,
            created_at,
            updated_at: now,
        };
        let out = resource_to_json(&entry);
        coll.insert(id.to_owned(), entry);
        Ok(out)
    }

    pub async fn delete(&self, tenant_id: &str, collection: &str, id: &str) -> bool {
        let mut guard = self.collections.write().await;
        guard
            .get_mut(&(tenant_id.to_owned(), collection.to_owned()))
            .and_then(|m| m.remove(id))
            .is_some()
    }
}

fn is_secret_key(key: &str) -> bool {
    let norm: String = key
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        norm.as_str(),
        "secret"
            | "clientsecret"
            | "signingsecret"
            | "webhooksecret"
            | "encryptedsecret"
            | "token"
            | "bearertoken"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "apikey"
            | "privatekey"
            | "secretkey"
            | "accesskey"
            | "password"
            | "passphrase"
            | "credential"
            | "credentials"
    ) || norm.ends_with("secret")
        || norm.ends_with("token")
        || norm.ends_with("password")
        || norm.ends_with("privatekey")
        || norm.ends_with("secretkey")
        || norm.ends_with("accesskey")
        || norm.ends_with("apikey")
        || norm.ends_with("credentials")
}

fn redact_value(val: &mut Value) {
    match val {
        Value::Object(map) => redact_map(map),
        Value::Array(arr) => {
            for item in arr {
                redact_value(item);
            }
        }
        _ => {}
    }
}

fn redact_map(map: &mut Map<String, Value>) {
    for (k, v) in map.iter_mut() {
        if is_secret_key(k) {
            *v = json!("[REDACTED]");
        } else {
            redact_value(v);
        }
    }
}

fn resource_to_json(res: &ManagedResource) -> Value {
    let mut obj = res.data.clone();
    redact_map(&mut obj);
    obj.insert("id".into(), json!(res.id));
    obj.insert("createdAt".into(), json!(res.created_at));
    obj.insert("updatedAt".into(), json!(res.updated_at));
    Value::Object(obj)
}

fn collection_policy(collection: &str, is_write: bool) -> RestPolicy {
    if collection.starts_with("/operator/") {
        return RestPolicy {
            scope: if is_write {
                "operator:write"
            } else {
                "operator:read"
            },
            alt_scope: None,
            assurance: if is_write {
                AssuranceRule::Confirmed
            } else {
                AssuranceRule::None
            },
            actor: if is_write {
                ActorRule::HumanOnly
            } else {
                ActorRule::AnyAuthenticated
            },
            plane: PlaneRule::OperatorOnly,
        };
    }
    if collection.starts_with("/provider/") {
        return RestPolicy {
            scope: if is_write {
                "provider:admin"
            } else {
                "provider:read"
            },
            alt_scope: if is_write {
                None
            } else {
                Some("provider:admin")
            },
            assurance: AssuranceRule::None,
            actor: if is_write {
                ActorRule::HumanOnly
            } else {
                ActorRule::AnyAuthenticated
            },
            plane: PlaneRule::ConsoleOnly,
        };
    }
    if collection.starts_with("/export-destinations") {
        return if is_write {
            RestPolicy::human_write("integrations:write", AssuranceRule::None)
        } else {
            RestPolicy::read("integrations:read")
        };
    }
    if is_write {
        RestPolicy::human_write("tenancy:write", AssuranceRule::None)
    } else {
        RestPolicy::read("tenancy:read")
    }
}

pub async fn list_collection_handler(
    Extension(catalog): Extension<ResourceCatalogStore>,
    Extension(auth): Extension<AuthContext>,
    collection: &'static str,
    response_key: &'static str,
) -> Response {
    if let Err(err) = authorize_rest(&auth, collection_policy(collection, false)) {
        return api_error_json_response(&err);
    }
    let items = catalog.list(&auth.tenant_id, collection).await;
    let mut map = Map::new();
    map.insert(response_key.into(), Value::Array(items));
    (StatusCode::OK, Json(Value::Object(map))).into_response()
}

pub async fn create_collection_handler(
    Extension(catalog): Extension<ResourceCatalogStore>,
    Extension(auth): Extension<AuthContext>,
    collection: &'static str,
    payload: Map<String, Value>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, collection_policy(collection, true)) {
        return api_error_json_response(&err);
    }
    match catalog.create(&auth.tenant_id, collection, payload).await {
        Ok(created) => (StatusCode::OK, Json(created)).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn get_collection_handler(
    Extension(catalog): Extension<ResourceCatalogStore>,
    Extension(auth): Extension<AuthContext>,
    collection: &'static str,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, collection_policy(collection, false)) {
        return api_error_json_response(&err);
    }
    match catalog.get(&auth.tenant_id, collection, &id).await {
        Some(v) => (StatusCode::OK, Json(v)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "code": "not_found", "message": "Resource not found" })),
        )
            .into_response(),
    }
}

pub async fn update_collection_handler(
    Extension(catalog): Extension<ResourceCatalogStore>,
    Extension(auth): Extension<AuthContext>,
    collection: &'static str,
    Path(id): Path<String>,
    payload: Map<String, Value>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, collection_policy(collection, true)) {
        return api_error_json_response(&err);
    }
    match catalog
        .upsert(&auth.tenant_id, collection, &id, payload)
        .await
    {
        Ok(updated) => (StatusCode::OK, Json(updated)).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn delete_collection_handler(
    Extension(catalog): Extension<ResourceCatalogStore>,
    Extension(auth): Extension<AuthContext>,
    collection: &'static str,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, collection_policy(collection, true)) {
        return api_error_json_response(&err);
    }
    if catalog.delete(&auth.tenant_id, collection, &id).await {
        (StatusCode::OK, Json(json!({ "deleted": true, "id": id }))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "code": "not_found", "message": "Resource not found" })),
        )
            .into_response()
    }
}
