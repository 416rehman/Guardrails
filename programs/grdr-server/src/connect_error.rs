// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64_STD;
use prost::Message as _;
use serde::Serialize;

use grdr_model::CodedError;
use grdr_model::error::{CODE_CONFLICT, CODE_NOT_FOUND, CODE_POLICY_DENIED, CODE_UNAUTHORIZED};
use grdr_proto::common::{ErrorClass, ErrorDetail, ErrorInfo};

use crate::aip::pagination::PaginationError;

pub const REQUEST_ID_HEADER: &str = "grdr-request-id";
pub const CODE_API_BAD_REQUEST: &str = "GRDR-API-0001";
pub const CODE_API_INVALID_FILTER: &str = "GRDR-API-0010";
pub const CODE_API_PAGE_TOKEN_INVALID: &str = "GRDR-API-0011";
pub const CODE_API_INVALID_ORDER: &str = "GRDR-API-0012";
pub const CODE_API_UNSUPPORTED_MEDIA: &str = "GRDR-API-0015";
pub const CODE_API_INTERNAL: &str = "GRDR-API-0099";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireEncoding {
    Json,
    Proto,
    ConnectJson,
    ConnectProto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectCode {
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    FailedPrecondition,
    Unimplemented,
    Internal,
}

#[derive(Debug, Clone)]
pub struct ApiErrorInner {
    pub code: ConnectCode,
    pub grdr_code: String,
    pub reason: String,
    pub class: ErrorClass,
    pub message: String,
    pub fix: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ApiError(Box<ApiErrorInner>);

#[derive(Debug, Serialize)]
struct ConnectErrorJson<'a> {
    code: &'static str,
    message: &'a str,
    details: Vec<ConnectErrorDetailJson>,
}

#[derive(Debug, Serialize)]
struct ConnectErrorDetailJson {
    #[serde(rename = "type")]
    type_url: &'static str,
    value: String,
    debug: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ConnectEndStreamError<'a> {
    error: ConnectErrorJson<'a>,
}

impl WireEncoding {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Proto => "application/proto",
            Self::ConnectJson => "application/connect+json",
            Self::ConnectProto => "application/connect+proto",
        }
    }

    pub fn is_framed(self) -> bool {
        matches!(self, Self::ConnectJson | Self::ConnectProto)
    }
}

impl ConnectCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::Unauthenticated => "unauthenticated",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::FailedPrecondition => "failed_precondition",
            Self::Unimplemented => "unimplemented",
            Self::Internal => "internal",
        }
    }

    pub fn http_status(self) -> StatusCode {
        match self {
            Self::InvalidArgument => StatusCode::BAD_REQUEST,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::PermissionDenied => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::FailedPrecondition => StatusCode::PRECONDITION_FAILED,
            Self::Unimplemented => StatusCode::NOT_IMPLEMENTED,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl ApiError {
    pub fn new(inner: ApiErrorInner) -> Self {
        Self(Box::new(inner))
    }

    pub fn invalid_argument(
        grdr_code: impl Into<String>,
        reason: impl Into<String>,
        message: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self::new(ApiErrorInner {
            code: ConnectCode::InvalidArgument,
            grdr_code: grdr_code.into(),
            reason: reason.into(),
            class: ErrorClass::Validation,
            message: message.into(),
            fix: fix.into(),
            metadata: BTreeMap::new(),
        })
    }

    pub fn unauthenticated(message: impl Into<String>, fix: impl Into<String>) -> Self {
        Self::new(ApiErrorInner {
            code: ConnectCode::Unauthenticated,
            grdr_code: CODE_UNAUTHORIZED.into(),
            reason: "UNAUTHENTICATED".into(),
            class: ErrorClass::Auth,
            message: message.into(),
            fix: fix.into(),
            metadata: BTreeMap::new(),
        })
    }

    pub fn from_coded(err: CodedError) -> Self {
        let (code, reason, class) = if err.code == CODE_NOT_FOUND {
            (
                ConnectCode::NotFound,
                "RESOURCE_NOT_FOUND",
                ErrorClass::NotFound,
            )
        } else if err.code == CODE_UNAUTHORIZED {
            (
                ConnectCode::Unauthenticated,
                "UNAUTHENTICATED",
                ErrorClass::Auth,
            )
        } else if err.code == CODE_CONFLICT {
            (
                ConnectCode::FailedPrecondition,
                "PRECONDITION_CONFLICT",
                ErrorClass::Conflict,
            )
        } else if err.code == CODE_POLICY_DENIED {
            (
                ConnectCode::PermissionDenied,
                "POLICY_DENIED",
                ErrorClass::Permission,
            )
        } else {
            (
                ConnectCode::InvalidArgument,
                "INVALID_ARGUMENT",
                ErrorClass::Validation,
            )
        };
        Self::new(ApiErrorInner {
            code,
            grdr_code: err.code,
            reason: reason.into(),
            class,
            message: err.message,
            fix: err.next_step,
            metadata: BTreeMap::new(),
        })
    }
}

impl From<CodedError> for ApiError {
    fn from(value: CodedError) -> Self {
        Self::from_coded(value)
    }
}

impl From<PaginationError> for ApiError {
    fn from(value: PaginationError) -> Self {
        match value {
            PaginationError::PageTokenInvalid => Self::invalid_argument(
                CODE_API_PAGE_TOKEN_INVALID,
                "PAGE_TOKEN_INVALID",
                "Invalid, mismatched, or expired page_token.",
                "Restart pagination from an empty page_token using the same filter and order_by.",
            ),
            PaginationError::InvalidFilter(err) => Self::invalid_argument(
                CODE_API_INVALID_FILTER,
                "INVALID_FILTER",
                err.to_string(),
                "Provide a bounded AIP-160 filter expression over allowlisted fields.",
            ),
            PaginationError::InvalidOrderBy(msg) => Self::invalid_argument(
                CODE_API_INVALID_ORDER,
                "INVALID_ORDER_BY",
                msg,
                "Order by a sortable field such as '<field> asc' or '<field> desc'.",
            ),
        }
    }
}

pub fn wrap_connect_frame(flags: u8, payload: &[u8]) -> Vec<u8> {
    let len_u32 = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(5usize.saturating_add(payload.len()));
    out.push(flags);
    out.extend_from_slice(&len_u32.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn apply_common_headers(headers: &mut HeaderMap, request_id: &str, etag: Option<&str>) {
    if let Ok(val) = HeaderValue::from_str(request_id) {
        headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), val);
    }
    if let Some(tag) = etag {
        if let Ok(val) = HeaderValue::from_str(tag) {
            headers.insert(header::ETAG, val);
        }
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-cache"),
        );
    }
}

pub fn encode_connect_error(encoding: WireEncoding, request_id: &str, err: &ApiError) -> Response {
    let err = &err.0;
    let mut info_meta = err.metadata.clone();
    info_meta.insert("code".into(), err.grdr_code.clone());
    info_meta.insert("request_id".into(), request_id.to_string());

    let error_info = ErrorInfo {
        reason: err.reason.clone(),
        domain: "grdr.api".into(),
        metadata: info_meta.clone(),
    };
    let error_detail = ErrorDetail {
        code: err.grdr_code.clone(),
        reason: err.reason.clone(),
        class: err.class as i32,
        message: err.message.clone(),
        message_id: err.grdr_code.clone(),
        fix: err.fix.clone(),
        docs_url: format!("https://guardrails.dev/docs/errors#{}", err.grdr_code),
        request_id: request_id.to_string(),
        metadata: info_meta,
    };

    let envelope = ConnectErrorJson {
        code: err.code.as_str(),
        message: &err.message,
        details: vec![
            ConnectErrorDetailJson {
                type_url: "google.rpc.ErrorInfo",
                value: B64_STD.encode(error_info.encode_to_vec()),
                debug: serde_json::to_value(&error_info).unwrap_or(serde_json::Value::Null),
            },
            ConnectErrorDetailJson {
                type_url: "grdr.common.v1alpha1.ErrorDetail",
                value: B64_STD.encode(error_detail.encode_to_vec()),
                debug: serde_json::to_value(&error_detail).unwrap_or(serde_json::Value::Null),
            },
        ],
    };

    let (status, ct, bytes) = if encoding.is_framed() {
        let end_stream = ConnectEndStreamError { error: envelope };
        let payload = serde_json::to_vec(&end_stream).unwrap_or_else(|_| b"{}".to_vec());
        (
            StatusCode::OK,
            encoding.content_type(),
            wrap_connect_frame(0x02, &payload),
        )
    } else {
        let payload = serde_json::to_vec(&envelope).unwrap_or_else(|_| b"{}".to_vec());
        (err.code.http_status(), "application/json", payload)
    };

    let mut resp = (status, bytes).into_response();
    if let Ok(ct_val) = HeaderValue::from_str(ct) {
        resp.headers_mut().insert(header::CONTENT_TYPE, ct_val);
    }
    apply_common_headers(resp.headers_mut(), request_id, None);
    resp
}
