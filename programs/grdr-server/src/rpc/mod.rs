// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod activity;
pub mod inventory;
pub mod overview;
pub mod policy;
pub mod response;
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

use grdr_proto::common::{CollectionKind, RevisionMeta, find_method};

use crate::aip::filter::FilterFieldSpec;
use crate::aip::pagination::{KeysetItem, OrderSpec, PageContext, PagedSlice, paginate_keyset};
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
const DEFAULT_PRINCIPAL: &str = "operator";

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
                class: grdr_proto::common::ErrorClass::Internal,
                message: format!("Unknown RPC method {method_path}"),
                fix: "Check generated service path.".into(),
                metadata: std::collections::BTreeMap::new(),
            }),
        );
    };

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

    match handler(state, req_msg).await {
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

pub fn page_collection<T: KeysetItem + Clone>(
    state: &AppState,
    items: Vec<T>,
    params: PageParams<'_>,
    spec: CollectionPageSpec,
) -> Result<(PagedSlice<T>, RevisionMeta), ApiError> {
    let hwm = state.revisions.current(spec.collection);
    let ctx = PageContext {
        tenant: DEFAULT_TENANT,
        principal: DEFAULT_PRINCIPAL,
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
        .meta_for(spec.collection, DEFAULT_TENANT, &digest_seed);
    Ok((paged, rev))
}

pub fn revision_for(state: &AppState, collection: CollectionKind, seed: &str) -> RevisionMeta {
    state.revisions.meta_for(collection, DEFAULT_TENANT, seed)
}
