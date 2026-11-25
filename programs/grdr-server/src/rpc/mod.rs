// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod activity;
pub mod inventory;
pub mod operator;
pub mod overview;
pub mod policy;
pub mod response;
pub mod surfaces;
pub mod tenancy;
pub mod verdict;

use std::future::Future;

use axum::body::{Body, to_bytes};
use axum::http::Request;
use axum::response::Response;
use jiff::Timestamp;
use prost::Message;
use serde::Serialize;
use serde::de::DeserializeOwned;

use grdr_proto::common::{CollectionKind, ConfirmClass, ErrorClass, RevisionMeta, find_method};

use crate::aip::filter::FilterFieldSpec;
use crate::aip::pagination::{KeysetItem, OrderSpec, PageContext, PagedSlice, paginate_keyset};
use crate::auth::{AuthContext, AuthPlane, ConfirmAssertion};
use crate::connect_codec::{
    decode_connect_request, encode_connect_response, extract_request_id, negotiate_encoding,
};
use crate::connect_error::{
    ApiError, ApiErrorInner, CODE_API_BAD_REQUEST, CODE_API_INTERNAL, ConnectCode, WireEncoding,
    encode_connect_error,
};
use crate::store::AppState;

const MAX_RPC_BODY_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_TENANT: &str = "org-default";
const DEFAULT_PRINCIPAL: &str = "console-admin";
const PUBLIC_HEALTH_PATH: &str = "/grdr.api.overview.v1alpha1.OverviewService/GetHealth";
const OPERATOR_SVC: &str = "grdr.api.operator.v1alpha1.OperatorService";
const OPERATOR_ALLOWED_OVERVIEW_PATHS: &[&str] = &[
    PUBLIC_HEALTH_PATH,
    "/grdr.api.overview.v1alpha1.OverviewService/GetOverview",
    "/grdr.api.overview.v1alpha1.OverviewService/ListKeys",
    "/grdr.api.overview.v1alpha1.OverviewService/ExportOcsf",
    "/grdr.api.overview.v1alpha1.OverviewService/ExportAuditJsonl",
    "/grdr.api.response.v1alpha1.ResponseService/ListAuditEvents",
];

pub struct PageParams<'a> {
    pub page_size: u32,
    pub page_token: &'a str,
    pub filter: &'a str,
    pub order_by: &'a str,
}

pub struct CollectionPageSpec {
    pub collection: CollectionKind,
    pub method: &'static str,
    pub allowed_filters: &'static [FilterFieldSpec],
    pub allowed_sort: &'static [&'static str],
    pub default_order: OrderSpec,
}

pub async fn run_rpc<Req, Resp, F, Fut>(
    method_path: &'static str,
    state: AppState,
    request: Request<Body>,
    handler: F,
) -> Response
where
    Req: Message + DeserializeOwned + Default,
    Resp: Message + Serialize,
    F: FnOnce(AppState, Req) -> Fut,
    Fut: Future<Output = Result<(Resp, Option<RevisionMeta>), ApiError>>,
{
    run_rpc_ctx(method_path, state, request, |state, _auth, req| {
        handler(state, req)
    })
    .await
}

pub async fn run_rpc_ctx<Req, Resp, F, Fut>(
    method_path: &'static str,
    state: AppState,
    request: Request<Body>,
    handler: F,
) -> Response
where
    Req: Message + DeserializeOwned + Default,
    Resp: Message + Serialize,
    F: FnOnce(AppState, AuthContext, Req) -> Fut,
    Fut: Future<Output = Result<(Resp, Option<RevisionMeta>), ApiError>>,
{
    let (parts, body) = request.into_parts();
    let request_id = extract_request_id(&parts.headers);
    let encoding = match negotiate_encoding(&parts.method, &parts.headers, &parts.uri) {
        Ok(enc) => enc,
        Err(err) => return encode_connect_error(WireEncoding::Json, &request_id, &err),
    };

    let Some(desc) = find_method(method_path) else {
        return encode_connect_error(
            encoding,
            &request_id,
            &ApiError::new(ApiErrorInner {
                code: ConnectCode::Unimplemented,
                grdr_code: CODE_API_INTERNAL.into(),
                reason: "METHOD_UNIMPLEMENTED".into(),
                class: ErrorClass::Internal,
                message: format!("Unknown RPC method {method_path}"),
                fix: "Check generated service path.".into(),
                metadata: std::collections::BTreeMap::new(),
            }),
        );
    };

    let auth = if method_path == PUBLIC_HEALTH_PATH {
        AuthContext {
            principal_id: "public-health".into(),
            tenant_id: DEFAULT_TENANT.into(),
            plane: AuthPlane::Console,
            scopes: vec!["overview:read".into()],
            confirmation: ConfirmAssertion::None,
        }
    } else if let Some(ctx) = parts.extensions.get::<AuthContext>().cloned() {
        ctx
    } else {
        return encode_connect_error(
            encoding,
            &request_id,
            &ApiError::unauthenticated(
                "Missing server authentication context.",
                "Authenticate via Bearer token before invoking this RPC.",
            ),
        );
    };

    if let Err(err) = authorize_descriptor(desc, &auth) {
        return encode_connect_error(encoding, &request_id, &err);
    }

    let bytes = match to_bytes(body, MAX_RPC_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            return encode_connect_error(
                encoding,
                &request_id,
                &ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "BODY_TOO_LARGE",
                    format!("Request body read failed: {e}"),
                    "Reduce request payload size below 2 MiB.",
                ),
            );
        }
    };

    let (enc, req_msg) = match decode_connect_request::<Req>(
        desc,
        &parts.method,
        &parts.headers,
        &parts.uri,
        &bytes,
    ) {
        Ok(pair) => pair,
        Err(err) => return encode_connect_error(encoding, &request_id, &err),
    };

    match handler(state, auth, req_msg).await {
        Ok((resp_msg, rev)) => {
            let etag = rev.as_ref().map(|r| r.etag.as_str());
            encode_connect_response(
                enc,
                &parts.method,
                &parts.headers,
                &request_id,
                etag,
                &resp_msg,
            )
        }
        Err(err) => encode_connect_error(enc, &request_id, &err),
    }
}

fn authorize_descriptor(
    desc: &grdr_proto::common::MethodDescriptor,
    auth: &AuthContext,
) -> Result<(), ApiError> {
    if desc.service == OPERATOR_SVC && auth.plane != AuthPlane::Operator {
        return Err(permission_denied_err(
            "OperatorService requires the dedicated Operator Plane listener and realm (D-70).",
            "Send operator RPCs to --operator-bind with --operator-token.",
        ));
    }
    if auth.plane == AuthPlane::Operator
        && desc.service != OPERATOR_SVC
        && !OPERATOR_ALLOWED_OVERVIEW_PATHS.contains(&desc.path)
    {
        return Err(permission_denied_err(
            "Operator Plane cannot access tenant content or policy APIs (D-70).",
            "Administer tenant resources on the tenant Console listener.",
        ));
    }
    if !auth.allows_scope(desc.scope) {
        return Err(permission_denied_err(
            &format!(
                "Missing required scope `{}` for {}.",
                desc.scope, desc.method
            ),
            "Authenticate with a principal carrying the required scope.",
        ));
    }
    if !matches!(desc.confirm, ConfirmClass::None | ConfirmClass::Unspecified)
        && !auth.confirmation.is_confirmed()
    {
        return Err(ApiError::new(ApiErrorInner {
            code: ConnectCode::FailedPrecondition,
            grdr_code: CODE_API_BAD_REQUEST.into(),
            reason: "CONFIRMATION_REQUIRED".into(),
            class: ErrorClass::Validation,
            message: format!(
                "Explicit confirmation intent required for {} ({:?}).",
                desc.method, desc.confirm
            ),
            fix: "Confirm the action explicitly via X-Grdr-Confirm before submitting.".into(),
            metadata: std::collections::BTreeMap::new(),
        }));
    }
    Ok(())
}

fn permission_denied_err(message: &str, fix: &str) -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::PermissionDenied,
        grdr_code: "GRDR-AUTH-0403".into(),
        reason: "PERMISSION_DENIED".into(),
        class: ErrorClass::Permission,
        message: message.into(),
        fix: fix.into(),
        metadata: std::collections::BTreeMap::new(),
    })
}

pub fn page_collection<T: KeysetItem + Clone>(
    state: &AppState,
    items: Vec<T>,
    params: PageParams<'_>,
    spec: CollectionPageSpec,
) -> Result<(PagedSlice<T>, RevisionMeta), ApiError> {
    let default_ctx = AuthContext {
        principal_id: DEFAULT_PRINCIPAL.into(),
        tenant_id: DEFAULT_TENANT.into(),
        plane: AuthPlane::Console,
        scopes: Vec::new(),
        confirmation: ConfirmAssertion::None,
    };
    page_collection_ctx(state, &default_ctx, items, params, spec)
}

pub fn page_collection_ctx<T: KeysetItem + Clone>(
    state: &AppState,
    auth: &AuthContext,
    items: Vec<T>,
    params: PageParams<'_>,
    spec: CollectionPageSpec,
) -> Result<(PagedSlice<T>, RevisionMeta), ApiError> {
    let hwm = state.revisions.current(spec.collection);
    let tenant = auth.tenant_id.as_str();
    let ctx = PageContext {
        tenant,
        principal: auth.principal_id.as_str(),
        method: spec.method,
        page_size: params.page_size,
        page_token: params.page_token,
        filter: params.filter,
        order_by: params.order_by,
        hwm,
        now: Timestamp::now(),
    };
    let paged = paginate_keyset(
        items,
        &ctx,
        &state.page_key,
        spec.allowed_filters,
        spec.allowed_sort,
        spec.default_order,
    )?;
    let digest_seed = format!(
        "ps={}&pt={}&f={}&o={}",
        params.page_size, params.page_token, params.filter, params.order_by
    );
    let rev = state
        .revisions
        .meta_for(spec.collection, tenant, &digest_seed);
    Ok((paged, rev))
}

pub fn revision_for(state: &AppState, collection: CollectionKind, seed: &str) -> RevisionMeta {
    state.revisions.meta_for(collection, DEFAULT_TENANT, seed)
}

pub fn revision_for_ctx(
    state: &AppState,
    auth: &AuthContext,
    collection: CollectionKind,
    seed: &str,
) -> RevisionMeta {
    state.revisions.meta_for(collection, &auth.tenant_id, seed)
}
