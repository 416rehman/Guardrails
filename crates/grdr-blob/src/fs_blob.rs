// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::UNIX_EPOCH;

use grdr_crypto::sha256_hex;
use uuid::Uuid;

use grdr_model::CodedError;
use grdr_ports::{
    BlobMetadata, BlobObject, BlobPort, BlobVersionCondition, ByteRange, CODE_BLOB_ALREADY_EXISTS,
    CODE_BLOB_INVALID_PATH, CODE_BLOB_INVALID_RANGE, CODE_BLOB_IO, CODE_BLOB_VERSION_CONFLICT,
    CODE_TENANT_SCOPE_MISMATCH, OrgId, SingleCtx, TenantCtx, TenantPath, TenantRelPath,
};

const INTERNAL_TMP_DIR: &str = ".tmp";
const INTERNAL_VERSIONS_DIR: &str = ".versions";

#[derive(Debug)]
pub struct FilesystemBlobStore {
    root_dir: PathBuf,
    write_lock: Mutex<()>,
}

impl FilesystemBlobStore {
    pub fn open(root_dir: &Path) -> Result<Self, CodedError> {
        fs::create_dir_all(root_dir).map_err(|e| blob_io(root_dir, &e))?;
        let canonical = fs::canonicalize(root_dir).map_err(|e| blob_io(root_dir, &e))?;
        Ok(Self {
            root_dir: canonical,
            write_lock: Mutex::new(()),
        })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    fn lock_write(&self) -> Result<MutexGuard<'_, ()>, CodedError> {
        self.write_lock.lock().map_err(|_| {
            CodedError::new(
                CODE_BLOB_IO,
                "Filesystem blob store write lock poisoned.",
                "Recreate FilesystemBlobStore.",
            )
        })
    }

    fn org_root(&self, org: &OrgId) -> Result<PathBuf, CodedError> {
        let dir = self.root_dir.join(format!("org={}", org.as_str()));
        fs::create_dir_all(&dir).map_err(|e| blob_io(&dir, &e))?;
        let canonical = fs::canonicalize(&dir).map_err(|e| blob_io(&dir, &e))?;
        if !canonical.starts_with(&self.root_dir) {
            return Err(CodedError::new(
                CODE_BLOB_INVALID_PATH,
                "Organisation blob directory escaped storage root.",
                "Verify filesystem layout and symlinks.",
            ));
        }
        Ok(canonical)
    }

    fn resolve_object_path(
        &self,
        path: &TenantPath,
        create_parents: bool,
    ) -> Result<(PathBuf, PathBuf), CodedError> {
        let org_root = self.org_root(path.organisation_id())?;
        let mut target = org_root.clone();
        for seg in path.relative().segments() {
            target.push(seg);
        }
        if let Some(parent) = target.parent() {
            if create_parents {
                fs::create_dir_all(parent).map_err(|e| blob_io(parent, &e))?;
            }
            if parent.exists() {
                let canon_parent = fs::canonicalize(parent).map_err(|e| blob_io(parent, &e))?;
                if !canon_parent.starts_with(&org_root) {
                    return Err(CodedError::new(
                        CODE_BLOB_INVALID_PATH,
                        "Blob parent directory escapes tenant scope.",
                        "Remove symlinks inside blob directory.",
                    ));
                }
            }
        }
        if target.exists() {
            let meta = fs::symlink_metadata(&target).map_err(|e| blob_io(&target, &e))?;
            if meta.file_type().is_symlink() {
                return Err(CodedError::new(
                    CODE_BLOB_INVALID_PATH,
                    "Symlink targets are forbidden in tenant blob storage.",
                    "Store regular files only inside TenantPath.",
                ));
            }
        }
        Ok((org_root, target))
    }

    fn write_atomic(&self, org_root: &Path, target: &Path, bytes: &[u8]) -> Result<(), CodedError> {
        let tmp_dir = org_root.join(INTERNAL_TMP_DIR);
        fs::create_dir_all(&tmp_dir).map_err(|e| blob_io(&tmp_dir, &e))?;
        let tmp_path = tmp_dir.join(format!("blob-{}.tmp", Uuid::now_v7().simple()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .map_err(|e| blob_io(&tmp_path, &e))?;
        file.write_all(bytes).map_err(|e| blob_io(&tmp_path, &e))?;
        file.sync_all().map_err(|e| blob_io(&tmp_path, &e))?;
        drop(file);
        fs::rename(&tmp_path, target).map_err(|e| blob_io(target, &e))?;
        Ok(())
    }

    fn archive_previous_version(
        &self,
        org_root: &Path,
        target: &Path,
        path: &TenantPath,
    ) -> Result<(), CodedError> {
        if !target.is_file() {
            return Ok(());
        }
        let existing = fs::read(target).map_err(|e| blob_io(target, &e))?;
        let ver_dir = org_root.join(INTERNAL_VERSIONS_DIR);
        fs::create_dir_all(&ver_dir).map_err(|e| blob_io(&ver_dir, &e))?;
        let ver_name = format!(
            "{}__{}.ver",
            path.relative().as_str().replace('/', "__"),
            Uuid::now_v7().simple()
        );
        let ver_path = ver_dir.join(ver_name);
        fs::write(&ver_path, existing).map_err(|e| blob_io(&ver_path, &e))?;
        Ok(())
    }
}

impl BlobPort for FilesystemBlobStore {
    fn put(
        &self,
        ctx: &SingleCtx,
        path: &TenantPath,
        bytes: &[u8],
    ) -> Result<BlobMetadata, CodedError> {
        check_single_scope(ctx, path)?;
        let _guard = self.lock_write()?;
        let (org_root, target) = self.resolve_object_path(path, true)?;
        self.write_atomic(&org_root, &target, bytes)?;
        let etag = sha256_hex(bytes);
        let updated_at_ms = file_mtime_ms(&target);
        Ok(BlobMetadata {
            path: path.clone(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            version_id: Some(etag.clone()),
            etag,
            updated_at_ms,
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
        let _guard = self.lock_write()?;
        let (org_root, target) = self.resolve_object_path(path, true)?;

        match condition {
            BlobVersionCondition::CreateOnly => {
                if target.exists() {
                    return Err(CodedError::new(
                        CODE_BLOB_ALREADY_EXISTS,
                        "Versioned blob already exists.",
                        "Use IfMatch with the current etag or write a new key.",
                    ));
                }
            }
            BlobVersionCondition::IfMatch(expected) => {
                if !target.is_file() {
                    return Err(CodedError::new(
                        CODE_BLOB_VERSION_CONFLICT,
                        "Cannot satisfy IfMatch for missing blob.",
                        "Use CreateOnly for initial creation.",
                    ));
                }
                let current_bytes = fs::read(&target).map_err(|e| blob_io(&target, &e))?;
                let current_etag = sha256_hex(&current_bytes);
                if &current_etag != expected {
                    return Err(CodedError::new(
                        CODE_BLOB_VERSION_CONFLICT,
                        "Blob etag precondition failed.",
                        "Reload object metadata and retry.",
                    ));
                }
                self.archive_previous_version(&org_root, &target, path)?;
            }
        }

        self.write_atomic(&org_root, &target, bytes)?;
        let etag = sha256_hex(bytes);
        let updated_at_ms = file_mtime_ms(&target);
        Ok(BlobMetadata {
            path: path.clone(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            version_id: Some(etag.clone()),
            etag,
            updated_at_ms,
        })
    }

    fn get(&self, ctx: &TenantCtx, path: &TenantPath) -> Result<Option<BlobObject>, CodedError> {
        check_read_scope(ctx, path)?;
        let (_org_root, target) = self.resolve_object_path(path, false)?;
        if !target.is_file() {
            return Ok(None);
        }
        let bytes = fs::read(&target).map_err(|e| blob_io(&target, &e))?;
        let etag = sha256_hex(&bytes);
        let updated_at_ms = file_mtime_ms(&target);
        let metadata = BlobMetadata {
            path: path.clone(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            version_id: Some(etag.clone()),
            etag,
            updated_at_ms,
        };
        Ok(Some(BlobObject { metadata, bytes }))
    }

    fn get_range(
        &self,
        ctx: &TenantCtx,
        path: &TenantPath,
        range: ByteRange,
    ) -> Result<Option<Vec<u8>>, CodedError> {
        check_read_scope(ctx, path)?;
        let (_org_root, target) = self.resolve_object_path(path, false)?;
        if !target.is_file() {
            return Ok(None);
        }
        let meta = fs::metadata(&target).map_err(|e| blob_io(&target, &e))?;
        if range.offset > meta.len() {
            return Err(CodedError::new(
                CODE_BLOB_INVALID_RANGE,
                "Byte range offset exceeds object size.",
                "Request a range within object bounds.",
            ));
        }
        let mut file = fs::File::open(&target).map_err(|e| blob_io(&target, &e))?;
        file.seek(SeekFrom::Start(range.offset))
            .map_err(|e| blob_io(&target, &e))?;
        let mut buf = Vec::new();
        file.take(range.length)
            .read_to_end(&mut buf)
            .map_err(|e| blob_io(&target, &e))?;
        Ok(Some(buf))
    }

    fn list(
        &self,
        ctx: &TenantCtx,
        prefix: &TenantRelPath,
    ) -> Result<Vec<BlobMetadata>, CodedError> {
        let mut out = Vec::new();
        for org in ctx.organisation_ids() {
            let org_dir = self.root_dir.join(format!("org={}", org.as_str()));
            if !org_dir.is_dir() {
                continue;
            }
            let canon_org = fs::canonicalize(&org_dir).map_err(|e| blob_io(&org_dir, &e))?;
            if !canon_org.starts_with(&self.root_dir) {
                continue;
            }
            walk_org_dir(&canon_org, &canon_org, org, prefix.as_str(), &mut out)?;
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    fn delete(&self, ctx: &SingleCtx, path: &TenantPath) -> Result<bool, CodedError> {
        check_single_scope(ctx, path)?;
        let _guard = self.lock_write()?;
        let (_org_root, target) = self.resolve_object_path(path, false)?;
        if !target.is_file() {
            return Ok(false);
        }
        fs::remove_file(&target).map_err(|e| blob_io(&target, &e))?;
        Ok(true)
    }
}

fn walk_org_dir(
    org_root: &Path,
    current: &Path,
    org: &OrgId,
    prefix: &str,
    out: &mut Vec<BlobMetadata>,
) -> Result<(), CodedError> {
    let entries = fs::read_dir(current).map_err(|e| blob_io(current, &e))?;
    for entry_res in entries {
        let entry = entry_res.map_err(|e| blob_io(current, &e))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| blob_io(&path, &e))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk_org_dir(org_root, &path, org, prefix, out)?;
        } else if meta.is_file() {
            let Ok(rel) = path.strip_prefix(org_root) else {
                continue;
            };
            let rel_str = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if !prefix.is_empty() && !rel_str.starts_with(prefix) {
                continue;
            }
            let Ok(rel_path) = TenantRelPath::parse(&rel_str) else {
                continue;
            };
            let bytes = fs::read(&path).map_err(|e| blob_io(&path, &e))?;
            let etag = sha256_hex(&bytes);
            let updated_at_ms = file_mtime_ms(&path);
            out.push(BlobMetadata {
                path: TenantPath::for_org(org.clone(), rel_path),
                size_bytes: meta.len(),
                version_id: Some(etag.clone()),
                etag,
                updated_at_ms,
            });
        }
    }
    Ok(())
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

fn blob_io(path: &Path, err: &std::io::Error) -> CodedError {
    CodedError::new(
        CODE_BLOB_IO,
        format!("Blob filesystem I/O failed at {}: {err}", path.display()),
        "Verify blob storage directory permissions and disk space.",
    )
}

fn file_mtime_ms(path: &Path) -> i64 {
    fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}
