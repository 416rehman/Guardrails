// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod compaction;
mod crypto;
mod erasure;
mod flush;
mod fuse_filter;
mod manifest_verify;
mod parquet_codec;
mod parquet_modular;
mod parquet_schema;
mod query;
mod query_eval;
mod retention;
mod schema;
mod store;
mod thrift_compact;

pub use store::LakeStore;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use grdr_blob::FilesystemBlobStore;
    use grdr_crypto::AeadKey;
    use grdr_ports::{
        BlobPort, CODE_LAKE_INVALID_QUERY, EventsPort, FencingToken, LakeBatch, LakeObservable,
        LakeQueryIr, LakeRecord, OrgId, RetentionClass, SingleCtx, TenantCtx, TenantPath,
    };
    use grdr_ports_testkit::MemoryBlobStore;

    use super::*;

    fn test_record(
        event_id: &str,
        root_session_id: &str,
        observed_time_ms: i64,
        received_at_ms: i64,
    ) -> LakeRecord {
        let mut fields = BTreeMap::new();
        fields.insert("action_class".into(), "exec".into());
        fields.insert("target".into(), "cargo test".into());
        let mut content_fields = BTreeMap::new();
        content_fields.insert("prompt_body".into(), "top-secret-prompt".into());
        LakeRecord {
            event_id: event_id.into(),
            device_id: "dev-1".into(),
            epoch: 1,
            lane: "evidence".into(),
            seq: 1,
            retention_class: RetentionClass::Content,
            category: "tool".into(),
            root_session_id: root_session_id.into(),
            session_id: root_session_id.into(),
            tool_call_id: None,
            observed_time_ms,
            monotonic_ns: 1_000,
            received_at_ms,
            schema_rev: 1,
            fields,
            content_fields,
            observables: vec![LakeObservable {
                observable_type: "host".into(),
                value: "vault.example.test".into(),
            }],
        }
    }

    #[test]
    fn lake_store_passes_events_port_contract() {
        let kek = AeadKey::generate().unwrap();
        let store = LakeStore::open_in_memory(MemoryBlobStore::default(), kek)
            .unwrap()
            .with_pitr_lag_ms(0);
        grdr_ports_testkit::assert_events_port_contract(&store).unwrap();
    }

    #[test]
    fn lake_store_seals_segments_and_reduces_archive_blobs_on_erasure() {
        let dir =
            std::env::temp_dir().join(format!("grdr-lake-fs-{}", uuid::Uuid::now_v7().simple()));
        let _ = std::fs::remove_dir_all(&dir);
        let kek = AeadKey::generate().unwrap();
        let blobs = FilesystemBlobStore::open(&dir.join("blobs")).unwrap();
        let lake = LakeStore::open(&dir.join("catalogue.sqlite3"), blobs, kek.clone()).unwrap();

        let org = OrgId::new("org-lake-seal").unwrap();
        let ctx = SingleCtx::new(org.clone());
        let read_ctx = TenantCtx::Single(ctx.clone());
        let fence = FencingToken::new(1);
        let now_ms = 1_700_000_000_000i64;
        let rec = test_record("evt-seal-1", "sess-seal", now_ms, now_ms);

        lake.append(
            &ctx,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: 1,
                lane: "evidence".into(),
                records: vec![rec],
                archive_bytes: b"raw-secret-archive-bytes".to_vec(),
            },
        )
        .unwrap();
        let flush_res = lake.flush(&ctx, fence, now_ms + 1_000, now_ms).unwrap();
        assert_eq!(flush_res.rows_flushed, 1);
        assert_eq!(flush_res.archive_segments_written, 1);

        let manifest = lake.manifest(&read_ctx).unwrap().unwrap();
        let seg_key = &manifest.entries[0].object_key;
        let raw_blob =
            std::fs::read(dir.join("blobs").join("org=org-lake-seal").join(seg_key)).unwrap();
        assert!(!String::from_utf8_lossy(&raw_blob).contains("top-secret-prompt"));
        assert!(!String::from_utf8_lossy(&raw_blob).contains("vault.example.test"));

        let arch_files: Vec<_> = std::fs::read_dir(
            dir.join("blobs")
                .join("org=org-lake-seal")
                .join("class=archive")
                .join("lane=evidence"),
        )
        .unwrap()
        .collect();
        assert_eq!(arch_files.len(), 1);
        let arch_path = arch_files[0].as_ref().unwrap().path();
        let arch_seg_file = std::fs::read_dir(&arch_path)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let raw_arch_before = std::fs::read(&arch_seg_file).unwrap();
        assert!(!String::from_utf8_lossy(&raw_arch_before).contains("raw-secret-archive-bytes"));

        let reopened_blobs = FilesystemBlobStore::open(&dir.join("blobs")).unwrap();
        let reopened =
            LakeStore::open(&dir.join("catalogue.sqlite3"), reopened_blobs, kek).unwrap();
        let timeline = reopened
            .execute_query_ir(
                &read_ctx,
                &LakeQueryIr::Timeline {
                    root_session_id: "sess-seal".into(),
                    include_content: true,
                    limit: 10,
                },
            )
            .unwrap();
        assert_eq!(timeline.rows.len(), 1);
        assert_eq!(
            timeline.rows[0]
                .columns
                .get("content.prompt_body")
                .map(String::as_str),
            Some("top-secret-prompt")
        );

        let wrong_kek = AeadKey::generate().unwrap();
        let wrong_blobs = FilesystemBlobStore::open(&dir.join("blobs")).unwrap();
        let wrong_lake =
            LakeStore::open(&dir.join("catalogue.sqlite3"), wrong_blobs, wrong_kek).unwrap();
        assert!(
            wrong_lake
                .execute_query_ir(
                    &read_ctx,
                    &LakeQueryIr::Timeline {
                        root_session_id: "sess-seal".into(),
                        include_content: true,
                        limit: 10,
                    },
                )
                .is_err()
        );

        let receipt = reopened
            .erase_session(&ctx, "sess-seal", "GDPR", now_ms + 2_000)
            .unwrap();
        assert_eq!(receipt.archive_segments_reduced, 1);

        let arch_after = std::fs::read(&arch_seg_file).unwrap();
        assert_ne!(raw_arch_before, arch_after);
        let rel_arch_key = format!(
            "class=archive/lane=evidence/{}/{}",
            arch_path.file_name().unwrap().to_string_lossy(),
            arch_seg_file.file_name().unwrap().to_string_lossy()
        );
        let day_dir = arch_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .strip_prefix("day=")
            .unwrap()
            .to_string();
        let (_, arch_dek) =
            crate::crypto::derive_segment_dek(reopened.org_kek(), &org, "archive", &day_dir);
        let decrypted_arch = crate::crypto::open_envelope(
            &arch_dek,
            crate::crypto::archive_seal_domain(),
            &[org.as_str(), "archive", &day_dir, &rel_arch_key],
            &arch_after,
        )
        .unwrap();
        let parsed_arch: crate::crypto::ArchivePayload =
            serde_json::from_slice(&decrypted_arch).unwrap();
        assert!(parsed_arch.raw_archive_b64.is_none());
        assert!(parsed_arch.records[0].content_fields.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lake_pitr_lag_and_adversarial_queries_enforced() {
        let kek = AeadKey::generate().unwrap();
        let lake = LakeStore::open_in_memory(MemoryBlobStore::default(), kek).unwrap();
        let org = OrgId::new("org-pitr").unwrap();
        let ctx = SingleCtx::new(org);
        let read_ctx = TenantCtx::Single(ctx.clone());
        let fence = FencingToken::new(1);
        let rx_ms = 1_700_000_000_000i64;
        let backdated_obs = rx_ms - (120 * 86_400_000);
        let rec = test_record("evt-pitr-1", "sess-pitr", backdated_obs, rx_ms);

        lake.append(
            &ctx,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: 1,
                lane: "evidence".into(),
                records: vec![rec],
                archive_bytes: Vec::new(),
            },
        )
        .unwrap();
        let flush = lake.flush(&ctx, fence, rx_ms + 1_000, rx_ms).unwrap();
        assert_eq!(flush.rows_flushed, 1);

        let manifest = lake.manifest(&read_ctx).unwrap().unwrap();
        let seg_key = &manifest.entries[0].object_key;
        let rx_day = crate::crypto::day_from_ms(rx_ms - (30 * 86_400_000)).unwrap();
        assert!(seg_key.contains(&format!("day={rx_day}")));

        let expired_ms = rx_ms + 86_400_000;
        let c1 = lake.compact_and_retain(&ctx, fence, expired_ms).unwrap();
        assert_eq!(c1.segments_logically_deleted, 1);
        assert_eq!(c1.segments_physically_deleted, 0);
        assert!(
            lake.blobs()
                .get(&read_ctx, &TenantPath::parse(&ctx, seg_key).unwrap())
                .unwrap()
                .is_some()
        );

        let after_pitr = expired_ms + (7 * 86_400_000);
        let c2 = lake.compact_and_retain(&ctx, fence, after_pitr).unwrap();
        assert_eq!(c2.segments_physically_deleted, 1);
        assert!(
            lake.blobs()
                .get(&read_ctx, &TenantPath::parse(&ctx, seg_key).unwrap())
                .unwrap()
                .is_none()
        );

        for bad_sql in [
            "SELECT event_id FROM activity WHERE target = 'x' OR 1=1",
            "SELECT content.prompt_body FROM content",
            "SELECT event_id FROM unknown_table",
            "SELECT event_id FROM activity; DROP TABLE lake_segments",
        ] {
            let err = lake
                .execute_query_ir(
                    &read_ctx,
                    &LakeQueryIr::Hunt {
                        sql_select: bad_sql.into(),
                        include_content: false,
                        limit: 10,
                    },
                )
                .unwrap_err();
            assert_eq!(err.code, CODE_LAKE_INVALID_QUERY);
        }

        let bad_cursor = lake
            .execute_query_ir(
                &read_ctx,
                &LakeQueryIr::Export {
                    retention_class: None,
                    cursor: Some("not-a-number".into()),
                    include_content: false,
                    limit: 10,
                },
            )
            .unwrap_err();
        assert_eq!(bad_cursor.code, CODE_LAKE_INVALID_QUERY);

        // Verify SetCtx Aggregate separates rows by OrgId rather than merging tenants.
        let org_a = OrgId::new("org-pitr").unwrap();
        let org_b = OrgId::new("org-pitr-b").unwrap();
        let ctx_b = SingleCtx::new(org_b.clone());
        let rec_a2 = test_record("evt-a-2", "sess-a2", rx_ms, rx_ms);
        lake.append(
            &ctx,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: 2,
                lane: "evidence".into(),
                records: vec![rec_a2],
                archive_bytes: Vec::new(),
            },
        )
        .unwrap();
        let rec_b = test_record("evt-b-1", "sess-b", rx_ms, rx_ms);
        lake.append(
            &ctx_b,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: 1,
                lane: "evidence".into(),
                records: vec![rec_b],
                archive_bytes: Vec::new(),
            },
        )
        .unwrap();
        let both = TenantCtx::set("snap-agg", vec![org_a, org_b]).unwrap();
        let agg = lake
            .execute_query_ir(
                &both,
                &LakeQueryIr::Aggregate {
                    retention_class: RetentionClass::Content,
                    group_by: vec!["action_class".into()],
                    aggregations: vec![grdr_ports::LakeAggSpec {
                        alias: "cnt".into(),
                        op: grdr_ports::LakeAggOp::Count,
                        field: None,
                    }],
                    predicates: vec![],
                },
            )
            .unwrap();
        assert_eq!(agg.rows.len(), 2);
    }

    #[test]
    fn lake_flush_preserves_memtable_when_blob_put_fails() {
        struct FailPutBlobs;
        impl BlobPort for FailPutBlobs {
            fn put(
                &self,
                _ctx: &SingleCtx,
                _path: &TenantPath,
                _bytes: &[u8],
            ) -> Result<grdr_ports::BlobMetadata, grdr_model::CodedError> {
                Err(grdr_model::CodedError::new(
                    grdr_ports::CODE_BLOB_IO,
                    "simulated blob failure",
                    "retry",
                ))
            }
            fn put_versioned(
                &self,
                ctx: &SingleCtx,
                path: &TenantPath,
                bytes: &[u8],
                _cond: &grdr_ports::BlobVersionCondition,
            ) -> Result<grdr_ports::BlobMetadata, grdr_model::CodedError> {
                self.put(ctx, path, bytes)
            }
            fn get(
                &self,
                _ctx: &TenantCtx,
                _path: &TenantPath,
            ) -> Result<Option<grdr_ports::BlobObject>, grdr_model::CodedError> {
                Ok(None)
            }
            fn get_range(
                &self,
                _ctx: &TenantCtx,
                _path: &TenantPath,
                _range: grdr_ports::ByteRange,
            ) -> Result<Option<Vec<u8>>, grdr_model::CodedError> {
                Ok(None)
            }
            fn list(
                &self,
                _ctx: &TenantCtx,
                _prefix: &grdr_ports::TenantRelPath,
            ) -> Result<Vec<grdr_ports::BlobMetadata>, grdr_model::CodedError> {
                Ok(Vec::new())
            }
            fn delete(
                &self,
                _ctx: &SingleCtx,
                _path: &TenantPath,
            ) -> Result<bool, grdr_model::CodedError> {
                Ok(false)
            }
        }

        let kek = AeadKey::generate().unwrap();
        let lake = LakeStore::open_in_memory(FailPutBlobs, kek).unwrap();
        let ctx = SingleCtx::new(OrgId::new("org-fail-flush").unwrap());
        let fence = FencingToken::new(1);
        let now_ms = 1_700_000_000_000i64;
        lake.append(
            &ctx,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: 1,
                lane: "evidence".into(),
                records: vec![test_record("evt-fail", "sess-fail", now_ms, now_ms)],
                archive_bytes: Vec::new(),
            },
        )
        .unwrap();
        assert!(lake.flush(&ctx, fence, now_ms + 1_000, now_ms).is_err());

        // Memtable must still hold the unflushed record so queries do not lose it.
        let res = lake
            .execute_query_ir(
                &TenantCtx::Single(ctx),
                &LakeQueryIr::Timeline {
                    root_session_id: "sess-fail".into(),
                    include_content: true,
                    limit: 10,
                },
            )
            .unwrap();
        assert_eq!(res.rows.len(), 1);
    }

    #[test]
    fn lake_parquet_par1_codec_and_thrift_metadata_roundtrip() {
        let now_ms = 1_700_000_000_000i64;
        let mut r1 = test_record("evt-par1-1", "sess-par1", now_ms, now_ms);
        r1.tool_call_id = Some("tc-1".into());
        let r2 = test_record("evt-par1-2", "sess-par1", now_ms + 500, now_ms + 500);

        let mut kv = BTreeMap::new();
        kv.insert("grdr.org_id".into(), "org-par1".into());
        let par1 = parquet_codec::encode_standard_par1(&[r1.clone(), r2.clone()], &kv).unwrap();
        assert_eq!(&par1[..4], b"PAR1");
        assert_eq!(&par1[par1.len() - 4..], b"PAR1");

        let meta = parquet_codec::decode_par1_footer(&par1).unwrap();
        assert_eq!(meta.num_rows, 2);
        assert_eq!(meta.columns.len(), parquet_codec::LAKE_COLUMNS.len());
        assert_eq!(
            meta.key_value_metadata
                .get("grdr.org_id")
                .map(String::as_str),
            Some("org-par1")
        );

        let kek = AeadKey::generate().unwrap();
        let org = OrgId::new("org-par1").unwrap();
        let (key_id, day_dek) =
            crypto::derive_segment_dek(&kek, &org, RetentionClass::Content.as_str(), "2023-11-14");
        let rel_key = "class=content/day=2023-11-14/seg-test.parquet";
        let sealed = parquet_modular::seal_modular_parquet(
            &org,
            RetentionClass::Content,
            "2023-11-14",
            rel_key,
            &key_id,
            &day_dek,
            &[r1.clone(), r2.clone()],
        )
        .unwrap();
        let opened = parquet_modular::open_modular_parquet(
            &org,
            RetentionClass::Content,
            "2023-11-14",
            rel_key,
            &day_dek,
            &sealed,
            None,
        )
        .unwrap();
        assert_eq!(opened, vec![r1, r2]);
    }

    #[test]
    fn lake_thrift_dos_bool_list_varint_overflow_pare_bounds_and_fuse_filter() {
        use grdr_ports::{CODE_LAKE_IO, RetentionClass};

        // 11-byte Thrift bool-list DoS payload claiming massive list len over zero-byte booleans.
        let mut r_bool = thrift_compact::CompactReader::new(&[
            0x19, 0xF1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00,
        ]);
        let err_skip = r_bool.skip_field(thrift_compact::CT_STRUCT).unwrap_err();
        assert_eq!(err_skip.code, CODE_LAKE_IO);

        // Standalone bool list with 2^64-1 elements must fail in O(1) against remaining_bytes().
        let err_meta = parquet_schema::decode_file_metadata(&[
            0x19, 0xF1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00,
        ])
        .unwrap_err();
        assert_eq!(err_meta.code, CODE_LAKE_IO);

        // 10th byte > 1 overflows u64 varint cleanly.
        let err_varint = parquet_schema::decode_file_metadata(&[
            0x36, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02, 0x00,
        ])
        .unwrap_err();
        assert_eq!(err_varint.code, CODE_LAKE_IO);

        // Oversized Parquet row count is rejected before allocation.
        let mut w_huge_rows = thrift_compact::CompactWriter::new();
        w_huge_rows.begin_struct();
        w_huge_rows.write_i64_field(3, 2_000_000_000);
        w_huge_rows.end_struct();
        assert_eq!(
            parquet_schema::decode_file_metadata(&w_huge_rows.into_bytes())
                .unwrap_err()
                .code,
            CODE_LAKE_IO
        );

        // Fuse filter rejects segment_len mismatches and non-empty zero-segment payloads.
        let bad_seg = [0u8; 8]
            .into_iter()
            .chain(100u64.to_le_bytes())
            .chain([1u8, 2u8])
            .collect::<Vec<_>>();
        assert!(fuse_filter::ObservableFuseFilter::decode(&bad_seg).is_none());
        let bad_zero = [0u8; 8]
            .into_iter()
            .chain(0u64.to_le_bytes())
            .chain([1u8, 2u8])
            .collect::<Vec<_>>();
        assert!(fuse_filter::ObservableFuseFilter::decode(&bad_zero).is_none());
        let empty = fuse_filter::ObservableFuseFilter::build(&[]);
        assert!(fuse_filter::ObservableFuseFilter::decode(&empty.encode()).is_some());

        // Oversized PARE header length in tail fails closed before calling get_range for header.
        let blobs = MemoryBlobStore::default();
        let org = OrgId::new("org-pare-bounds").unwrap();
        let sctx = SingleCtx::new(org.clone());
        let tctx = TenantCtx::Single(sctx.clone());
        let path = TenantPath::parse(&sctx, "class=content/day=2023-11-14/bad.parquet").unwrap();
        let mut forged = vec![0u8; 32];
        forged.extend_from_slice(&(64_000_000u32).to_le_bytes());
        forged.extend_from_slice(parquet_modular::PARQUET_MAGIC_PARE);
        let size_hint = u64::try_from(forged.len()).unwrap();
        blobs.put(&sctx, &path, &forged).unwrap();
        let kek = AeadKey::generate().unwrap();
        let (_, dek) =
            crypto::derive_segment_dek(&kek, &org, RetentionClass::Content.as_str(), "2023-11-14");
        let err_pare = parquet_modular::read_modular_parquet_projected(
            &blobs,
            &tctx,
            &path,
            size_hint,
            &parquet_modular::ParquetSliceDecryptCtx {
                org_id: &org,
                class: RetentionClass::Content,
                day: "2023-11-14",
                rel_key: "class=content/day=2023-11-14/bad.parquet",
                day_dek: &dek,
            },
            None,
        )
        .unwrap_err();
        assert_eq!(err_pare.code, CODE_LAKE_IO);
    }
}
