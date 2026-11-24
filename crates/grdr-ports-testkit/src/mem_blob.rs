// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use sha2::{Digest, Sha256};

use grdr_model::CodedError;
use grdr_model::error::CODE_STORE_IO;
use grdr_ports::{
    BlobMetadata, BlobObject, BlobPort, BlobVersionCondition, ByteRange, CODE_BLOB_ALREADY_EXISTS,
    CODE_BLOB_INVALID_RANGE, CODE_BLOB_VERSION_CONFLICT, CODE_TENANT_SCOPE_MISMATCH, SingleCtx,
    TenantCtx, TenantPath, TenantRelPath,
};

#[derive(Debug, Default)]
struct MemBlobInner {
    objects: BTreeMap<String, BlobObject>,
    versions: BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
pub struct MemoryBlobStore {
    inner: Mutex<MemBlobInner>,
}

impl BlobPort for MemoryBlobStore {
    fn put(
        &self,
        ctx: &SingleCtx,
        path: &TenantPath,
        bytes: &[u8],
    ) -> Result<BlobMetadata, CodedError> {
        check_single_blob_scope(ctx, path)?;
        let mut g = lock_blob(&self.inner)?;
        let key = path.scoped_key();
        let next_ver = g.versions.get(&key).copied().unwrap_or(0).saturating_add(1);
        g.versions.insert(key.clone(), next_ver);
        let meta = BlobMetadata {
            path: path.clone(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            version_id: Some(format!("v{next_ver}")),
            etag: sha256_hex(bytes),
            updated_at_ms: 0,
        };
        g.objects.insert(
            key,
            BlobObject {
                metadata: meta.clone(),
                bytes: bytes.to_vec(),
            },
        );
        Ok(meta)
    }

    fn put_versioned(
        &self,
        ctx: &SingleCtx,
        path: &TenantPath,
        bytes: &[u8],
        condition: &BlobVersionCondition,
    ) -> Result<BlobMetadata, CodedError> {
        check_single_blob_scope(ctx, path)?;
        let mut g = lock_blob(&self.inner)?;
        let key = path.scoped_key();
        match (condition, g.objects.get(&key)) {
            (BlobVersionCondition::CreateOnly, Some(_)) => {
                return Err(CodedError::new(
                    CODE_BLOB_ALREADY_EXISTS,
                    "Versioned blob already exists.",
                    "Use IfMatch with the current etag or write a new key.",
                ));
            }
            (BlobVersionCondition::IfMatch(expected), Some(existing))
                if &existing.metadata.etag != expected =>
            {
                return Err(CodedError::new(
                    CODE_BLOB_VERSION_CONFLICT,
                    "Blob etag precondition failed.",
                    "Reload the object metadata and retry.",
                ));
            }
            (BlobVersionCondition::IfMatch(_), None) => {
                return Err(CodedError::new(
                    CODE_BLOB_VERSION_CONFLICT,
                    "Cannot satisfy IfMatch for missing blob.",
                    "Use CreateOnly for initial creation.",
                ));
            }
            _ => {}
        }
        let next_ver = g.versions.get(&key).copied().unwrap_or(0).saturating_add(1);
        g.versions.insert(key.clone(), next_ver);
        let meta = BlobMetadata {
            path: path.clone(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            version_id: Some(format!("v{next_ver}")),
            etag: sha256_hex(bytes),
            updated_at_ms: 0,
        };
        g.objects.insert(
            key,
            BlobObject {
                metadata: meta.clone(),
                bytes: bytes.to_vec(),
            },
        );
        Ok(meta)
    }

    fn get(&self, ctx: &TenantCtx, path: &TenantPath) -> Result<Option<BlobObject>, CodedError> {
        if !ctx.contains(path.organisation_id()) {
            return Err(CodedError::new(
                CODE_TENANT_SCOPE_MISMATCH,
                "TenantCtx does not authorise reading this TenantPath.",
                "Pass a TenantCtx containing the target organisation.",
            ));
        }
        let g = lock_blob(&self.inner)?;
        Ok(g.objects.get(&path.scoped_key()).cloned())
    }

    fn get_range(
        &self,
        ctx: &TenantCtx,
        path: &TenantPath,
        range: ByteRange,
    ) -> Result<Option<Vec<u8>>, CodedError> {
        let Some(obj) = self.get(ctx, path)? else {
            return Ok(None);
        };
        let total = u64::try_from(obj.bytes.len()).unwrap_or(u64::MAX);
        if range.offset > total {
            return Err(CodedError::new(
                CODE_BLOB_INVALID_RANGE,
                "Byte range offset exceeds object size.",
                "Request a range within object bounds.",
            ));
        }
        let start = usize::try_from(range.offset).unwrap_or(usize::MAX);
        let len = usize::try_from(range.length).unwrap_or(usize::MAX);
        let end = start.saturating_add(len).min(obj.bytes.len());
        Ok(obj.bytes.get(start..end).map(ToOwned::to_owned))
    }

    fn list(
        &self,
        ctx: &TenantCtx,
        prefix: &TenantRelPath,
    ) -> Result<Vec<BlobMetadata>, CodedError> {
        let g = lock_blob(&self.inner)?;
        let prefix_str = prefix.as_str();
        let mut out = Vec::new();
        for obj in g.objects.values() {
            if !ctx.contains(obj.metadata.path.organisation_id()) {
                continue;
            }
            let rel = obj.metadata.path.relative().as_str();
            if prefix_str.is_empty() || rel.starts_with(prefix_str) {
                out.push(obj.metadata.clone());
            }
        }
        Ok(out)
    }

    fn delete(&self, ctx: &SingleCtx, path: &TenantPath) -> Result<bool, CodedError> {
        check_single_blob_scope(ctx, path)?;
        let mut g = lock_blob(&self.inner)?;
        Ok(g.objects.remove(&path.scoped_key()).is_some())
    }
}

fn lock_blob<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, CodedError> {
    mutex.lock().map_err(|_| {
        CodedError::new(
            CODE_STORE_IO,
            "In-memory blob testkit mutex poisoned.",
            "Recreate MemoryBlobStore.",
        )
    })
}

fn check_single_blob_scope(ctx: &SingleCtx, path: &TenantPath) -> Result<(), CodedError> {
    if ctx.organisation_id() != path.organisation_id() {
        return Err(CodedError::new(
            CODE_TENANT_SCOPE_MISMATCH,
            "SingleCtx organisation does not match TenantPath organisation.",
            "Build TenantPath from the active SingleCtx.",
        ));
    }
    Ok(())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
