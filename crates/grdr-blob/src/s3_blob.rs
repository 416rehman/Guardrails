// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use grdr_crypto::sha256_hex;
use grdr_model::CodedError;
use grdr_ports::{
    BlobMetadata, BlobObject, BlobPort, BlobVersionCondition, ByteRange, CODE_BLOB_ALREADY_EXISTS,
    CODE_BLOB_INVALID_RANGE, CODE_BLOB_IO, CODE_BLOB_VERSION_CONFLICT, CODE_TENANT_SCOPE_MISMATCH,
    OrgId, SingleCtx, TenantCtx, TenantPath, TenantRelPath,
};

use crate::s3_config::{S3BlobConfig, S3LifecycleMode};
use crate::s3_http::{S3HttpClient, S3HttpMethod, S3HttpRequest, S3HttpResponse, S3ResponseStatus};
use crate::s3_xml::{
    parse_lifecycle_present, parse_list_objects_v2, parse_s3_error, parse_versioning_status,
};

const MAX_LIST_PAGES: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3ConformanceReport {
    pub versioning_enabled: bool,
    pub has_bucket_lifecycle: bool,
    pub lifecycle_mode: S3LifecycleMode,
    pub detail: String,
}

#[derive(Debug)]
pub struct S3BlobStore {
    http: S3HttpClient,
}

impl S3BlobStore {
    pub fn connect(config: S3BlobConfig) -> Result<Self, CodedError> {
        let http = S3HttpClient::new(config)?;
        Ok(Self { http })
    }

    pub fn config(&self) -> &S3BlobConfig {
        self.http.config()
    }

    pub fn check_conformance(&self) -> Result<S3ConformanceReport, CodedError> {
        let ver_resp = self.http.execute(S3HttpRequest {
            method: S3HttpMethod::Get,
            key: None,
            query: vec![("versioning".into(), String::new())],
            extra_headers: Vec::new(),
            body: Vec::new(),
        })?;
        if ver_resp.status.is_error() {
            return Err(s3_status_error("GET ?versioning", &ver_resp));
        }
        let ver_xml = String::from_utf8_lossy(&ver_resp.body);
        let ver_status = parse_versioning_status(&ver_xml)?;
        let versioning_enabled = ver_status.as_deref() == Some("Enabled");

        let lc_resp = self.http.execute(S3HttpRequest {
            method: S3HttpMethod::Get,
            key: None,
            query: vec![("lifecycle".into(), String::new())],
            extra_headers: Vec::new(),
            body: Vec::new(),
        })?;
        let has_bucket_lifecycle = if lc_resp.status == S3ResponseStatus::Ok {
            let lc_xml = String::from_utf8_lossy(&lc_resp.body);
            parse_lifecycle_present(&lc_xml)?
        } else if lc_resp.status == S3ResponseStatus::NotFound {
            false
        } else {
            return Err(s3_status_error("GET ?lifecycle", &lc_resp));
        };

        let lifecycle_mode = self.http.config().lifecycle_mode;
        let detail = format!(
            "bucket={}, versioning_enabled={versioning_enabled}, bucket_lifecycle={has_bucket_lifecycle}, lifecycle_mode={lifecycle_mode:?}",
            self.http.config().bucket
        );
        Ok(S3ConformanceReport {
            versioning_enabled,
            has_bucket_lifecycle,
            lifecycle_mode,
            detail,
        })
    }

    pub fn require_versioned_conformance(&self) -> Result<S3ConformanceReport, CodedError> {
        let report = self.check_conformance()?;
        if !report.versioning_enabled {
            return Err(CodedError::new(
                CODE_BLOB_IO,
                format!(
                    "S3 bucket `{}` does not have object versioning Enabled.",
                    self.http.config().bucket
                ),
                "Enable object versioning on S3/SeaweedFS/Ceph RGW bucket before running HA storage.",
            ));
        }
        if !report.has_bucket_lifecycle && report.lifecycle_mode == S3LifecycleMode::BucketManaged {
            return Err(CodedError::new(
                CODE_BLOB_IO,
                format!(
                    "S3 bucket `{}` lacks bucket lifecycle rules under BucketManaged mode.",
                    self.http.config().bucket
                ),
                "Configure noncurrent-version expiry on the bucket or set lifecycle_mode=ServerManaged.",
            ));
        }
        Ok(report)
    }

    fn object_key(&self, path: &TenantPath) -> String {
        let rel = format!(
            "org={}/{}",
            path.organisation_id().as_str(),
            path.relative().as_str()
        );
        let prefix = self.http.config().normalized_prefix();
        if prefix.is_empty() {
            rel
        } else {
            format!("{prefix}/{rel}")
        }
    }

    fn list_prefix_key(&self, org: &OrgId, prefix: &TenantRelPath) -> String {
        let base = if prefix.as_str().is_empty() {
            format!("org={}/", org.as_str())
        } else {
            format!("org={}/{}", org.as_str(), prefix.as_str())
        };
        let root_prefix = self.http.config().normalized_prefix();
        if root_prefix.is_empty() {
            base
        } else {
            format!("{root_prefix}/{base}")
        }
    }

    fn strip_org_prefix(&self, org: &OrgId, key: &str) -> Option<String> {
        let root_prefix = self.http.config().normalized_prefix();
        let expected_org = format!("org={}/", org.as_str());
        let after_root = if root_prefix.is_empty() {
            key
        } else {
            key.strip_prefix(&format!("{root_prefix}/"))?
        };
        after_root
            .strip_prefix(&expected_org)
            .map(ToString::to_string)
    }
}

impl BlobPort for S3BlobStore {
    fn put(
        &self,
        ctx: &SingleCtx,
        path: &TenantPath,
        bytes: &[u8],
    ) -> Result<BlobMetadata, CodedError> {
        check_single_scope(ctx, path)?;
        let key = self.object_key(path);
        let resp = self.http.execute(S3HttpRequest {
            method: S3HttpMethod::Put,
            key: Some(key),
            query: Vec::new(),
            extra_headers: Vec::new(),
            body: bytes.to_vec(),
        })?;
        if resp.status.is_error() {
            return Err(s3_status_error("PUT object", &resp));
        }
        let etag = resp.etag.unwrap_or_else(|| sha256_hex(bytes));
        let now_ms = Timestamp::now().as_millisecond();
        Ok(BlobMetadata {
            path: path.clone(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(0),
            version_id: resp.version_id.or_else(|| Some(etag.clone())),
            etag,
            updated_at_ms: now_ms,
        })
    }

    fn put_versioned(
        &self,
        ctx: &SingleCtx,
        path: &TenantPath,
        bytes: &[u8],
        condition: &BlobVersionCondition,
    ) -> Result<BlobMetadata, CodedError> {
        check_single_scope(ctx, path)?;
        let key = self.object_key(path);
        let cond_header = match condition {
            BlobVersionCondition::CreateOnly => ("if-none-match".into(), "*".into()),
            BlobVersionCondition::IfMatch(expected) => {
                let clean = expected.trim();
                if clean.is_empty()
                    || clean.contains('"')
                    || clean
                        .chars()
                        .any(|c| c.is_control() || matches!(c, '\r' | '\n' | '\0'))
                {
                    return Err(CodedError::new(
                        CODE_BLOB_IO,
                        "Invalid S3 IfMatch ETag precondition value.",
                        "Supply a non-empty unquoted ETag without quotes or control characters.",
                    ));
                }
                ("if-match".into(), format!("\"{clean}\""))
            }
        };

        let resp = self.http.execute(S3HttpRequest {
            method: S3HttpMethod::Put,
            key: Some(key),
            query: Vec::new(),
            extra_headers: vec![cond_header],
            body: bytes.to_vec(),
        })?;
        if matches!(
            resp.status,
            S3ResponseStatus::PreconditionFailed | S3ResponseStatus::Conflict
        ) || (resp.status == S3ResponseStatus::NotFound
            && matches!(condition, BlobVersionCondition::IfMatch(_)))
        {
            return Err(match condition {
                BlobVersionCondition::CreateOnly => CodedError::new(
                    CODE_BLOB_ALREADY_EXISTS,
                    format!(
                        "S3 blob `{}` already exists (CreateOnly precondition failed).",
                        path.relative().as_str()
                    ),
                    "Use a new sequence key or conditional IfMatch update.",
                ),
                BlobVersionCondition::IfMatch(expected) => CodedError::new(
                    CODE_BLOB_VERSION_CONFLICT,
                    format!(
                        "S3 blob `{}` ETag precondition `{expected}` failed (HTTP {}).",
                        path.relative().as_str(),
                        resp.status.code()
                    ),
                    "Reload the latest blob version and retry.",
                ),
            });
        }
        if resp.status.is_error() {
            return Err(s3_status_error("PUT conditional object", &resp));
        }
        let etag = resp.etag.unwrap_or_else(|| sha256_hex(bytes));
        let now_ms = Timestamp::now().as_millisecond();
        Ok(BlobMetadata {
            path: path.clone(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(0),
            version_id: resp.version_id.or_else(|| Some(etag.clone())),
            etag,
            updated_at_ms: now_ms,
        })
    }

    fn get(&self, ctx: &TenantCtx, path: &TenantPath) -> Result<Option<BlobObject>, CodedError> {
        check_read_scope(ctx, path)?;
        let key = self.object_key(path);
        let resp = self.http.execute(S3HttpRequest {
            method: S3HttpMethod::Get,
            key: Some(key),
            query: Vec::new(),
            extra_headers: Vec::new(),
            body: Vec::new(),
        })?;
        if resp.status == S3ResponseStatus::NotFound {
            return Ok(None);
        }
        if resp.status.is_error() {
            return Err(s3_status_error("GET object", &resp));
        }
        let etag = resp.etag.unwrap_or_else(|| sha256_hex(&resp.body));
        let size_bytes = u64::try_from(resp.body.len()).unwrap_or(0);
        let now_ms = Timestamp::now().as_millisecond();
        Ok(Some(BlobObject {
            metadata: BlobMetadata {
                path: path.clone(),
                size_bytes,
                version_id: resp.version_id.or_else(|| Some(etag.clone())),
                etag,
                updated_at_ms: now_ms,
            },
            bytes: resp.body,
        }))
    }

    fn get_range(
        &self,
        ctx: &TenantCtx,
        path: &TenantPath,
        range: ByteRange,
    ) -> Result<Option<Vec<u8>>, CodedError> {
        check_read_scope(ctx, path)?;
        let key = self.object_key(path);
        if range.length == 0 {
            let head = self.http.execute(S3HttpRequest {
                method: S3HttpMethod::Head,
                key: Some(key),
                query: Vec::new(),
                extra_headers: Vec::new(),
                body: Vec::new(),
            })?;
            if head.status == S3ResponseStatus::NotFound {
                return Ok(None);
            }
            if head.status.is_error() {
                return Err(s3_status_error("HEAD object", &head));
            }
            if range.offset > head.content_length {
                return Err(invalid_range_err(
                    "Byte range offset exceeds S3 object size.",
                ));
            }
            return Ok(Some(Vec::new()));
        }

        let end_inclusive = range
            .offset
            .checked_add(range.length)
            .and_then(|v| v.checked_sub(1))
            .ok_or_else(|| invalid_range_err("Byte range overflows u64 bounds."))?;
        let range_hdr = format!("bytes={}-{}", range.offset, end_inclusive);

        let resp = self.http.execute(S3HttpRequest {
            method: S3HttpMethod::Get,
            key: Some(key),
            query: Vec::new(),
            extra_headers: vec![("range".into(), range_hdr)],
            body: Vec::new(),
        })?;
        if resp.status == S3ResponseStatus::NotFound {
            return Ok(None);
        }
        if resp.status == S3ResponseStatus::RangeNotSatisfiable {
            return Err(invalid_range_err(
                "S3 rejected byte range (416 Range Not Satisfiable).",
            ));
        }
        if resp.status.is_error() {
            return Err(s3_status_error("GET byte range", &resp));
        }
        if resp.status == S3ResponseStatus::Ok {
            let start = usize::try_from(range.offset)
                .map_err(|_| invalid_range_err("Byte range offset exceeds usize."))?;
            if start > resp.body.len() {
                return Err(invalid_range_err(
                    "Byte range offset exceeds object length.",
                ));
            }
            let max_len = usize::try_from(range.length).unwrap_or(usize::MAX);
            let end = start.saturating_add(max_len).min(resp.body.len());
            return Ok(Some(resp.body.get(start..end).unwrap_or(&[]).to_vec()));
        }
        if u64::try_from(resp.body.len())
            .ok()
            .is_none_or(|n| n > range.length)
        {
            return Err(invalid_range_err(
                "S3 range response exceeded requested ByteRange length.",
            ));
        }
        Ok(Some(resp.body))
    }

    fn list(
        &self,
        ctx: &TenantCtx,
        prefix: &TenantRelPath,
    ) -> Result<Vec<BlobMetadata>, CodedError> {
        let mut out = Vec::new();
        for org in ctx.organisation_ids() {
            let s3_prefix = self.list_prefix_key(org, prefix);
            let mut continuation: Option<String> = None;
            let mut completed = false;
            for _page in 0..MAX_LIST_PAGES {
                let mut query = vec![
                    ("list-type".into(), "2".into()),
                    ("prefix".into(), s3_prefix.clone()),
                ];
                if let Some(ref token) = continuation {
                    query.push(("continuation-token".into(), token.clone()));
                }
                let resp = self.http.execute(S3HttpRequest {
                    method: S3HttpMethod::Get,
                    key: None,
                    query,
                    extra_headers: Vec::new(),
                    body: Vec::new(),
                })?;
                if resp.status.is_error() {
                    return Err(s3_status_error("ListObjectsV2", &resp));
                }
                let xml = String::from_utf8_lossy(&resp.body);
                let page = parse_list_objects_v2(&xml)?;
                for entry in page.entries {
                    let Some(rel_str) = self.strip_org_prefix(org, &entry.key) else {
                        continue;
                    };
                    if let Ok(rel_path) = TenantRelPath::parse(&rel_str) {
                        out.push(BlobMetadata {
                            path: TenantPath::for_org(org.clone(), rel_path),
                            size_bytes: entry.size_bytes,
                            version_id: Some(entry.etag.clone()),
                            etag: entry.etag,
                            updated_at_ms: entry.last_modified_ms,
                        });
                    }
                }
                if !page.is_truncated {
                    completed = true;
                    break;
                }
                let Some(next_token) = page.next_continuation_token else {
                    return Err(CodedError::new(
                        CODE_BLOB_IO,
                        "S3 ListObjectsV2 reported IsTruncated=true without NextContinuationToken.",
                        "Inspect S3 ListObjectsV2 response integrity.",
                    ));
                };
                continuation = Some(next_token);
            }
            if !completed {
                return Err(CodedError::new(
                    CODE_BLOB_IO,
                    format!("S3 ListObjectsV2 exceeded {MAX_LIST_PAGES} pages without finishing."),
                    "Narrow list prefix or check S3 bucket continuation loop.",
                ));
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    fn delete(&self, ctx: &SingleCtx, path: &TenantPath) -> Result<bool, CodedError> {
        check_single_scope(ctx, path)?;
        let key = self.object_key(path);
        let head = self.http.execute(S3HttpRequest {
            method: S3HttpMethod::Head,
            key: Some(key.clone()),
            query: Vec::new(),
            extra_headers: Vec::new(),
            body: Vec::new(),
        })?;
        if head.status == S3ResponseStatus::NotFound {
            return Ok(false);
        }
        if head.status.is_error() {
            return Err(s3_status_error("HEAD before DELETE", &head));
        }

        let del = self.http.execute(S3HttpRequest {
            method: S3HttpMethod::Delete,
            key: Some(key),
            query: Vec::new(),
            extra_headers: Vec::new(),
            body: Vec::new(),
        })?;
        if del.status == S3ResponseStatus::NotFound {
            return Ok(false);
        }
        if del.status.is_error() {
            return Err(s3_status_error("DELETE object", &del));
        }
        Ok(true)
    }
}

fn check_single_scope(ctx: &SingleCtx, path: &TenantPath) -> Result<(), CodedError> {
    if ctx.organisation_id() != path.organisation_id() {
        return Err(CodedError::new(
            CODE_TENANT_SCOPE_MISMATCH,
            "SingleCtx organisation does not match TenantPath organisation.",
            "Construct TenantPath from the active SingleCtx.",
        ));
    }
    Ok(())
}

fn check_read_scope(ctx: &TenantCtx, path: &TenantPath) -> Result<(), CodedError> {
    if !ctx.contains(path.organisation_id()) {
        return Err(CodedError::new(
            CODE_TENANT_SCOPE_MISMATCH,
            "TenantCtx does not authorise reading this TenantPath.",
            "Pass a TenantCtx covering the target organisation.",
        ));
    }
    Ok(())
}

fn invalid_range_err(msg: &str) -> CodedError {
    CodedError::new(
        CODE_BLOB_INVALID_RANGE,
        msg,
        "Request a byte range within S3 object bounds.",
    )
}

fn s3_status_error(op: &str, resp: &S3HttpResponse) -> CodedError {
    let body_text = String::from_utf8_lossy(&resp.body);
    let code = resp.status.code();
    let detail = match parse_s3_error(&body_text) {
        Some(err) => format!("{op} failed (HTTP {code}, {}): {}", err.code, err.message),
        None => format!("{op} failed with HTTP status {code}"),
    };
    CodedError::new(
        CODE_BLOB_IO,
        detail,
        "Verify S3 bucket permissions, SigV4 clock skew, credentials, and endpoint.",
    )
}
