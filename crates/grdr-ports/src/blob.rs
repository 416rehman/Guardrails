// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;

use crate::tenant::{SingleCtx, TenantCtx, TenantPath, TenantRelPath};

pub const CODE_BLOB_IO: &str = "GRDR-BLOB-0002";
pub const CODE_BLOB_ALREADY_EXISTS: &str = "GRDR-BLOB-0003";
pub const CODE_BLOB_VERSION_CONFLICT: &str = "GRDR-BLOB-0004";
pub const CODE_BLOB_INVALID_RANGE: &str = "GRDR-BLOB-0005";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub path: TenantPath,
    pub size_bytes: u64,
    pub version_id: Option<String>,
    pub etag: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobObject {
    pub metadata: BlobMetadata,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobVersionCondition {
    CreateOnly,
    IfMatch(String),
}

pub trait BlobPort {
    fn put(
        &self,
        ctx: &SingleCtx,
        path: &TenantPath,
        bytes: &[u8],
    ) -> Result<BlobMetadata, CodedError>;

    fn put_versioned(
        &self,
        ctx: &SingleCtx,
        path: &TenantPath,
        bytes: &[u8],
        condition: &BlobVersionCondition,
    ) -> Result<BlobMetadata, CodedError>;

    fn get(&self, ctx: &TenantCtx, path: &TenantPath) -> Result<Option<BlobObject>, CodedError>;

    fn get_range(
        &self,
        ctx: &TenantCtx,
        path: &TenantPath,
        range: ByteRange,
    ) -> Result<Option<Vec<u8>>, CodedError>;

    fn list(
        &self,
        ctx: &TenantCtx,
        prefix: &TenantRelPath,
    ) -> Result<Vec<BlobMetadata>, CodedError>;

    fn delete(&self, ctx: &SingleCtx, path: &TenantPath) -> Result<bool, CodedError>;
}
