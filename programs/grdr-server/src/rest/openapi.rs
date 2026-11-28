// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use grdr_crypto::sha256_hex;
use grdr_proto::common::{ALL_METHODS, SURFACES_AND_OPERATOR_METHODS};
use grdr_proto::descriptor::load_embedded_descriptor_set;
use serde_json::{Map, Value, json};

use super::openapi_spec::{path_is_collection, rest_endpoint_specs};

pub const BRAND_TOML_RAW: &str = include_str!("../../../../contracts/interface/brand/brand.toml");

#[derive(Debug, Clone)]
pub struct BrandInfo {
    pub product_name: String,
    pub short_name: String,
    pub namespace: String,
    pub domain: String,
    pub copyright_holder: String,
}

impl BrandInfo {
    pub fn embedded() -> Self {
        Self::from_toml(BRAND_TOML_RAW)
    }

    pub fn from_toml(raw: &str) -> Self {
        Self {
            product_name: toml_str(raw, "product_name"),
            short_name: toml_str(raw, "short_name"),
            namespace: toml_str(raw, "namespace"),
            domain: toml_str(raw, "domain"),
            copyright_holder: toml_str(raw, "copyright_holder"),
        }
    }
}

fn toml_str(raw: &str, key: &str) -> String {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((lhs, rhs)) = trimmed.split_once('=')
            && lhs.trim() == key
            && let Some(inner) = rhs
                .trim()
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
        {
            return inner.to_owned();
        }
    }
    String::new()
}

pub fn build_openapi_document() -> Value {
    let brand = BrandInfo::embedded();
    let mut paths = Map::new();

    for &(path, method, summary, needs_idem) in rest_endpoint_specs() {
        let mut op = Map::new();
        op.insert("summary".into(), json!(summary));
        op.insert(
            "operationId".into(),
            json!(format!(
                "{}_{}",
                method,
                path.replace(['/', '{', '}', ':', '-'], "_")
            )),
        );
        if method == "get" && path_is_collection(path) {
            op.insert(
                "parameters".into(),
                json!([
                    { "name": "page_size", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 1000 } },
                    { "name": "page_token", "in": "query", "schema": { "type": "string" } },
                    { "name": "filter", "in": "query", "schema": { "type": "string" } },
                    { "name": "order_by", "in": "query", "schema": { "type": "string" } }
                ]),
            );
        } else if needs_idem {
            op.insert(
                "parameters".into(),
                json!([
                    { "name": "Idempotency-Key", "in": "header", "required": true, "schema": { "type": "string", "format": "uuid" } }
                ]),
            );
        }
        op.insert(
            "responses".into(),
            json!({
                "200": { "description": "Success", "content": { "application/json": { "schema": { "type": "object" } } } },
                "400": { "$ref": "#/components/responses/ErrorResponse" },
                "401": { "$ref": "#/components/responses/ErrorResponse" },
                "403": { "$ref": "#/components/responses/ErrorResponse" },
                "412": { "$ref": "#/components/responses/ErrorResponse" },
                "429": { "$ref": "#/components/responses/ErrorResponse" }
            }),
        );
        let entry = paths
            .entry(path)
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(obj) = entry {
            obj.insert(method.into(), Value::Object(op));
        }
    }

    let mut rpc_methods = Vec::new();
    for spec in ALL_METHODS
        .iter()
        .chain(SURFACES_AND_OPERATOR_METHODS.iter())
    {
        if spec.service.contains("OperatorService") {
            continue;
        }
        rpc_methods.push(json!({
            "service": spec.service,
            "method": spec.method,
            "connectPath": spec.path,
            "idempotency": format!("{:?}", spec.idempotency),
            "mcpExposed": spec.mcp_exposed,
        }));
    }

    let descriptor_file_count = load_embedded_descriptor_set()
        .map(|d| d.files.len())
        .unwrap_or(0);

    json!({
        "openapi": "3.1.0",
        "jsonSchemaDialect": "https://spec.openapis.org/oas/3.1/dialect/base",
        "info": {
            "title": format!("{} Control Plane API", brand.product_name),
            "version": env!("CARGO_PKG_VERSION"),
            "description": format!("Versioned REST /v1 and Connect gateway for {}.", brand.short_name),
            "contact": {
                "name": brand.copyright_holder,
                "url": format!("https://{}", brand.domain),
            },
            "license": {
                "name": "Apache-2.0"
            },
            "x-brand-namespace": brand.namespace
        },
        "servers": [
            { "url": "/v1", "description": "Control plane v1 REST base" }
        ],
        "security": [
            { "bearerAuth": [] }
        ],
        "paths": Value::Object(paths),
        "x-grdr-connect-methods": rpc_methods,
        "x-grdr-descriptor-files": descriptor_file_count,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            },
            "schemas": {
                "PageInfo": {
                    "type": "object",
                    "properties": {
                        "nextPageToken": { "type": "string" },
                        "prevPageToken": { "type": "string" },
                        "totalSizeEstimate": { "type": "integer" },
                        "hasMore": { "type": "boolean" }
                    }
                },
                "ApiError": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": { "type": "string" },
                        "reason": { "type": "string" },
                        "message": { "type": "string" },
                        "details": { "type": "array", "items": { "type": "object" } }
                    }
                },
                "PolicyChange": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "state": {
                            "type": "string",
                            "enum": ["DRAFT", "CHECKED", "FAILED", "AWAITING_APPROVAL", "ROLLING_OUT", "HALTED", "APPLIED", "DENIED", "SUPERSEDED"]
                        }
                    }
                },
                "WebhookEndpoint": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "url": { "type": "string", "format": "uri" },
                        "signingAlgorithm": { "type": "string", "enum": ["ed25519", "hmac_sha256"] }
                    }
                }
            },
            "responses": {
                "ErrorResponse": {
                    "description": "Structured Connect / RFC 9457 error payload",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ApiError" }
                        }
                    }
                }
            }
        }
    })
}

pub async fn get_openapi_json(headers: axum::http::HeaderMap) -> Response {
    let doc = build_openapi_document();
    let body = serde_json::to_vec(&doc).unwrap_or_else(|_| b"{}".to_vec());
    let etag = format!(
        "\"openapi-{}\"",
        sha256_hex(&body).get(..16).unwrap_or("v1")
    );
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == etag)
    {
        return (
            StatusCode::NOT_MODIFIED,
            [(
                header::ETAG,
                HeaderValue::from_str(&etag)
                    .unwrap_or_else(|_| HeaderValue::from_static("\"openapi\"")),
            )],
        )
            .into_response();
    }
    let mut resp = (StatusCode::OK, axum::Json(doc)).into_response();
    let hdrs = resp.headers_mut();
    if let Ok(val) = HeaderValue::from_str(&etag) {
        hdrs.insert(header::ETAG, val);
    }
    hdrs.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    resp
}
