// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod fs_blob;
mod s3_blob;
pub mod s3_config;
mod s3_http;
mod s3_sigv4;
mod s3_xml;

pub use fs_blob::FilesystemBlobStore;
pub use s3_blob::{S3BlobStore, S3ConformanceReport};
pub use s3_config::{
    S3AddressingStyle, S3BlobConfig, S3Credentials, S3LifecycleMode, S3TransportSecurity,
};

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_ports::{BlobPort, OrgId, SingleCtx, TenantCtx, TenantPath};

    #[test]
    fn filesystem_blob_passes_port_contract() {
        let dir = std::env::temp_dir().join(format!("grdr-blob-contract-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let blobs = FilesystemBlobStore::open(&dir).unwrap();
        grdr_ports_testkit::assert_blob_port_contract(&blobs).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn filesystem_blob_persists_across_reopen_and_blocks_traversal() {
        let dir = std::env::temp_dir().join(format!("grdr-blob-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let org = OrgId::new("org-fs-1").unwrap();
        let ctx = SingleCtx::new(org);
        assert!(TenantPath::parse(&ctx, "../../etc/passwd").is_err());

        let path = TenantPath::parse(&ctx, "manifests/daily.json").unwrap();
        {
            let blobs = FilesystemBlobStore::open(&dir).unwrap();
            blobs.put(&ctx, &path, b"{\"ok\":true}").unwrap();
        }

        let reopened = FilesystemBlobStore::open(&dir).unwrap();
        let read_ctx = TenantCtx::Single(ctx);
        let obj = reopened.get(&read_ctx, &path).unwrap().unwrap();
        assert_eq!(obj.bytes, b"{\"ok\":true}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
