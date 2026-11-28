// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use grdr_crypto::{AeadKey, SigningKeypair};
use grdr_lake::LakeStore;
use grdr_model::CodedError;
use grdr_ports::{
    BlobMetadata, BlobObject, BlobPort, BlobVersionCondition, ByteRange, CODE_LAKE_HOLD_ACTIVE,
    CODE_LAKE_INVALID_QUERY, CODE_LAKE_IO, EventsPort, FencingToken, LakeAggOp, LakeAggSpec,
    LakeBatch, LakeObservable, LakePredicate, LakeQueryIr, LakeRecord, LegalHoldRequest,
    LegalHoldScope, OrgId, RetentionClass, SingleCtx, TenantCtx, TenantPath, TenantRelPath,
};
use grdr_ports_testkit::MemoryBlobStore;

#[derive(Default)]
struct CountingBlobStore {
    inner: MemoryBlobStore,
    put_calls: AtomicUsize,
    get_calls: AtomicUsize,
    range_calls: AtomicUsize,
    range_bytes: AtomicU64,
    full_bytes: AtomicU64,
}

impl CountingBlobStore {
    fn reset_counters(&self) {
        self.put_calls.store(0, Ordering::SeqCst);
        self.get_calls.store(0, Ordering::SeqCst);
        self.range_calls.store(0, Ordering::SeqCst);
        self.range_bytes.store(0, Ordering::SeqCst);
        self.full_bytes.store(0, Ordering::SeqCst);
    }
}

impl BlobPort for CountingBlobStore {
    fn put(
        &self,
        ctx: &SingleCtx,
        path: &TenantPath,
        bytes: &[u8],
    ) -> Result<BlobMetadata, CodedError> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.put(ctx, path, bytes)
    }

    fn put_versioned(
        &self,
        ctx: &SingleCtx,
        path: &TenantPath,
        bytes: &[u8],
        condition: &BlobVersionCondition,
    ) -> Result<BlobMetadata, CodedError> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.put_versioned(ctx, path, bytes, condition)
    }

    fn get(&self, ctx: &TenantCtx, path: &TenantPath) -> Result<Option<BlobObject>, CodedError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        let res = self.inner.get(ctx, path)?;
        if let Some(ref obj) = res {
            self.full_bytes.fetch_add(
                u64::try_from(obj.bytes.len()).unwrap_or(0),
                Ordering::SeqCst,
            );
        }
        Ok(res)
    }

    fn get_range(
        &self,
        ctx: &TenantCtx,
        path: &TenantPath,
        range: ByteRange,
    ) -> Result<Option<Vec<u8>>, CodedError> {
        self.range_calls.fetch_add(1, Ordering::SeqCst);
        let res = self.inner.get_range(ctx, path, range)?;
        if let Some(ref chunk) = res {
            self.range_bytes
                .fetch_add(u64::try_from(chunk.len()).unwrap_or(0), Ordering::SeqCst);
        }
        Ok(res)
    }

    fn list(
        &self,
        ctx: &TenantCtx,
        prefix: &TenantRelPath,
    ) -> Result<Vec<BlobMetadata>, CodedError> {
        self.inner.list(ctx, prefix)
    }

    fn delete(&self, ctx: &SingleCtx, path: &TenantPath) -> Result<bool, CodedError> {
        self.inner.delete(ctx, path)
    }
}

fn make_record(
    event_id: &str,
    seq: u64,
    root_session_id: &str,
    prompt_body: &str,
    obs_host: Option<&str>,
    ts_ms: i64,
) -> LakeRecord {
    let mut fields = BTreeMap::new();
    fields.insert("action_class".into(), "exec".into());
    fields.insert("target".into(), format!("cmd-{event_id}"));
    let mut content_fields = BTreeMap::new();
    content_fields.insert("prompt_body".into(), prompt_body.to_string());
    let observables = obs_host
        .into_iter()
        .map(|h| LakeObservable {
            observable_type: "host".into(),
            value: h.to_string(),
        })
        .collect();
    LakeRecord {
        event_id: event_id.to_string(),
        device_id: "dev-1".into(),
        epoch: 1,
        lane: "evidence".into(),
        seq,
        retention_class: RetentionClass::Content,
        category: "tool".into(),
        root_session_id: root_session_id.to_string(),
        session_id: root_session_id.to_string(),
        tool_call_id: Some(format!("tc-{seq}")),
        observed_time_ms: ts_ms,
        monotonic_ns: seq.saturating_mul(1_000),
        received_at_ms: ts_ms,
        schema_rev: 1,
        fields,
        content_fields,
        observables,
    }
}

#[test]
fn lake_parquet_modular_encryption_per_session_erasure_and_cross_org_isolation() {
    let kek = AeadKey::generate().unwrap();
    let signer = SigningKeypair::generate().unwrap();
    let lake = LakeStore::open_in_memory(MemoryBlobStore::default(), kek.clone())
        .unwrap()
        .with_signing_key(signer);
    let org_a = OrgId::new("org-parquet-a").unwrap();
    let org_b = OrgId::new("org-parquet-b").unwrap();
    let ctx_a = SingleCtx::new(org_a.clone());
    let ctx_b = SingleCtx::new(org_b.clone());
    let read_a = TenantCtx::Single(ctx_a.clone());
    let read_b = TenantCtx::Single(ctx_b.clone());
    let fence = FencingToken::new(1);
    let now_ms = 1_700_000_000_000i64;

    let r_erased = make_record(
        "evt-erased",
        1,
        "sess-erase-me",
        "secret-to-shred",
        Some("erase.example.test"),
        now_ms,
    );
    let r_kept = make_record(
        "evt-kept",
        2,
        "sess-keep-me",
        "secret-stays-intact",
        Some("keep.example.test"),
        now_ms + 100,
    );

    lake.append(
        &ctx_a,
        fence,
        &LakeBatch {
            partition: 0,
            bus_offset: 1,
            lane: "evidence".into(),
            records: vec![r_erased, r_kept],
            archive_bytes: Vec::new(),
        },
    )
    .unwrap();
    let flush = lake.flush(&ctx_a, fence, now_ms + 1_000, now_ms).unwrap();
    assert_eq!(flush.segments_written, 1);

    let manifest = lake.manifest(&read_a).unwrap().unwrap();
    let seg_key = manifest.entries[0].object_key.clone();
    assert!(seg_key.ends_with(".parquet"));
    assert_eq!(lake.verify_manifest_chain(&read_a).unwrap(), 1);

    // Raw blob is PARE modular encrypted, revealing zero prompt plaintext.
    let raw_obj = lake
        .blobs()
        .get(&read_a, &TenantPath::parse(&ctx_a, &seg_key).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(&raw_obj.bytes[..4], b"PARE");
    assert_eq!(&raw_obj.bytes[raw_obj.bytes.len() - 4..], b"PARE");
    assert!(!String::from_utf8_lossy(&raw_obj.bytes).contains("secret-stays-intact"));
    assert!(!String::from_utf8_lossy(&raw_obj.bytes).contains("secret-to-shred"));

    // Standard decrypted PAR1 export validates magic and structure.
    let par1 = lake
        .export_segment_as_par1(&read_a, &org_a, &seg_key)
        .unwrap();
    assert_eq!(&par1[..4], b"PAR1");
    assert_eq!(&par1[par1.len() - 4..], b"PAR1");
    assert!(
        lake.export_segment_as_par1(&read_b, &org_a, &seg_key)
            .is_err()
    );

    // Cross-org copied object fails AEAD footer/column AAD under org_b's key/AAD context.
    let _ = kek;
    let r_b_dummy = make_record("evt-b-dummy", 1, "sess-b", "p-b", None, now_ms);
    lake.append(
        &ctx_b,
        fence,
        &LakeBatch {
            partition: 0,
            bus_offset: 1,
            lane: "evidence".into(),
            records: vec![r_b_dummy],
            archive_bytes: Vec::new(),
        },
    )
    .unwrap();
    lake.flush(&ctx_b, fence, now_ms + 1_000, now_ms).unwrap();
    let manifest_b = lake.manifest(&read_b).unwrap().unwrap();
    let key_b = manifest_b.entries[0].object_key.clone();
    lake.blobs()
        .put(
            &ctx_b,
            &TenantPath::parse(&ctx_b, &key_b).unwrap(),
            &raw_obj.bytes,
        )
        .unwrap();
    let err_swap = lake
        .export_segment_as_par1(&read_b, &org_b, &key_b)
        .unwrap_err();
    assert_eq!(err_swap.code, "GRDR-LAKE-0001");

    // GDPR erasure destroys ONLY sess-erase-me's content key; sess-keep-me in SAME file still reads!
    lake.erase_session(&ctx_a, "sess-erase-me", "user request", now_ms + 500)
        .unwrap();
    let tl_erased = lake
        .execute_query_ir(
            &read_a,
            &LakeQueryIr::Timeline {
                root_session_id: "sess-erase-me".into(),
                include_content: true,
                limit: 10,
            },
        )
        .unwrap();
    assert_eq!(tl_erased.rows.len(), 1);
    assert!(tl_erased.rows[0].content_redacted);
    assert!(
        !tl_erased.rows[0]
            .columns
            .contains_key("content.prompt_body")
    );

    let tl_kept = lake
        .execute_query_ir(
            &read_a,
            &LakeQueryIr::Timeline {
                root_session_id: "sess-keep-me".into(),
                include_content: true,
                limit: 10,
            },
        )
        .unwrap();
    assert_eq!(tl_kept.rows.len(), 1);
    assert!(!tl_kept.rows[0].content_redacted);
    assert_eq!(
        tl_kept.rows[0]
            .columns
            .get("content.prompt_body")
            .map(String::as_str),
        Some("secret-stays-intact")
    );
}

#[test]
fn lake_fuse_filter_projection_range_read_and_compaction_put_budgets() {
    let kek = AeadKey::generate().unwrap();
    let signer = SigningKeypair::generate().unwrap();
    let lake = LakeStore::open_in_memory(CountingBlobStore::default(), kek)
        .unwrap()
        .with_pitr_lag_ms(0)
        .with_signing_key(signer);
    let org = OrgId::new("org-fuse-proj").unwrap();
    let ctx = SingleCtx::new(org.clone());
    let read_ctx = TenantCtx::Single(ctx.clone());
    let fence = FencingToken::new(1);
    let base_ms = 1_700_000_000_000i64;
    let big_prompt = "large-confidential-prompt-payload-".repeat(80);

    // Flush 3 separate batches on same day -> 3 .parquet objects with Fuse Filters.
    for (idx, obs) in [
        Some("alpha.safe.test"),
        Some("needle.evil.test"),
        Some("gamma.safe.test"),
    ]
    .into_iter()
    .enumerate()
    {
        let seq = u64::try_from(idx + 1).unwrap();
        let rec = make_record(
            &format!("evt-fp-{seq}"),
            seq,
            &format!("sess-fp-{seq}"),
            &format!("{big_prompt}-secret-marker-{seq}"),
            obs,
            base_ms + (idx as i64 * 1_000),
        );
        lake.append(
            &ctx,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: seq,
                lane: "evidence".into(),
                records: vec![rec],
                archive_bytes: Vec::new(),
            },
        )
        .unwrap();
        lake.flush(&ctx, fence, base_ms + 10_000, base_ms + 10_000)
            .unwrap();
    }

    // Verify zero segment reads for absent observable via Fuse Filter pruning!
    lake.blobs().reset_counters();
    let absent = lake
        .execute_query_ir(
            &read_ctx,
            &LakeQueryIr::Lookup {
                observable_type: Some("host".into()),
                value: "definitely-absent.invalid".into(),
                limit: 10,
            },
        )
        .unwrap();
    assert!(absent.rows.is_empty());
    assert_eq!(absent.scanned_segments, 0);
    assert_eq!(lake.blobs().get_calls.load(Ordering::SeqCst), 0);
    assert_eq!(lake.blobs().range_calls.load(Ordering::SeqCst), 0);

    // Verify Lookup hits ONLY the matching 1/3 segment!
    lake.blobs().reset_counters();
    let hit = lake
        .execute_query_ir(
            &read_ctx,
            &LakeQueryIr::Lookup {
                observable_type: Some("host".into()),
                value: "needle.evil.test".into(),
                limit: 10,
            },
        )
        .unwrap();
    assert_eq!(hit.rows.len(), 1);
    assert_eq!(hit.scanned_segments, 1);

    // Verify columnar projection uses get_range and reads strictly fewer bytes than full blobs!
    let manifest = lake.manifest(&read_ctx).unwrap().unwrap();
    let manifest_key = &manifest.entries[0].object_key;
    let total_parquet_len = u64::try_from(
        lake.blobs()
            .get(&read_ctx, &TenantPath::parse(&ctx, manifest_key).unwrap())
            .unwrap()
            .unwrap()
            .bytes
            .len(),
    )
    .unwrap()
        * 3;
    lake.blobs().reset_counters();
    let proj_scan = lake
        .execute_query_ir(
            &read_ctx,
            &LakeQueryIr::Scan {
                retention_class: RetentionClass::Content,
                category: Some("tool".into()),
                predicates: vec![],
                projection: vec!["event_id".into(), "category".into()],
                include_content: false,
                limit: 20,
            },
        )
        .unwrap();
    assert_eq!(proj_scan.rows.len(), 3);
    assert_eq!(lake.blobs().get_calls.load(Ordering::SeqCst), 0);
    assert!(lake.blobs().range_calls.load(Ordering::SeqCst) > 0);
    assert!(lake.blobs().range_bytes.load(Ordering::SeqCst) < total_parquet_len);

    // L-8 free-text content search works when include_content == true, skipped when false.
    let content_hit = lake
        .execute_query_ir(
            &read_ctx,
            &LakeQueryIr::Scan {
                retention_class: RetentionClass::Content,
                category: None,
                predicates: vec![LakePredicate {
                    field: "content.prompt_body".into(),
                    equals: None,
                    contains: Some("secret-marker-2".into()),
                }],
                projection: vec![],
                include_content: true,
                limit: 10,
            },
        )
        .unwrap();
    assert_eq!(content_hit.rows.len(), 1);
    assert_eq!(content_hit.rows[0].event_id.as_deref(), Some("evt-fp-2"));

    // Compaction coalesces 3 day segments into 1 active object under PUT budget (<= 200).
    let cmp = lake
        .compact_and_retain(&ctx, fence, base_ms + 20_000)
        .unwrap();
    assert_eq!(cmp.segments_compacted, 1);
    let (puts, objs) = lake.daily_put_stats(&ctx, "2023-11-14").unwrap();
    assert_eq!(puts, 7);
    assert_eq!(objs, 4);
    assert!(puts <= 200);
    assert_eq!(lake.verify_manifest_chain(&read_ctx).unwrap(), 3);

    // Daily agg contains zero user/principal PII while recording exact counts.
    let agg = lake.daily_agg_rows(&ctx, "2023-11-14").unwrap();
    assert_eq!(agg, vec![("content".to_string(), "tool".to_string(), 3)]);
}

#[test]
fn lake_manifest_verification_fails_closed_without_trusted_signed_chain() {
    let kek = AeadKey::generate().unwrap();
    let org = OrgId::new("org-manifest-auth").unwrap();
    let ctx = SingleCtx::new(org);
    let read_ctx = TenantCtx::Single(ctx.clone());
    let fence = FencingToken::new(1);
    let now_ms = 1_700_000_000_000i64;

    // Unsigned lake rejects verify_manifest_chain (no trusted keys / unsigned rows).
    let unsigned_lake = LakeStore::open_in_memory(MemoryBlobStore::default(), kek.clone()).unwrap();
    let wrong_signer = SigningKeypair::generate().unwrap();
    assert_eq!(
        unsigned_lake
            .verify_manifest_chain_with_keys(&read_ctx, &[wrong_signer.public_key_bytes()])
            .unwrap_err()
            .code,
        CODE_LAKE_IO
    );
    let rec = make_record("evt-m-1", 1, "sess-m", "secret", None, now_ms);
    unsigned_lake
        .append(
            &ctx,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: 1,
                lane: "evidence".into(),
                records: vec![rec.clone()],
                archive_bytes: Vec::new(),
            },
        )
        .unwrap();
    unsigned_lake
        .flush(&ctx, fence, now_ms + 1_000, now_ms)
        .unwrap();
    assert_eq!(
        unsigned_lake
            .verify_manifest_chain(&read_ctx)
            .unwrap_err()
            .code,
        CODE_LAKE_IO
    );
    assert_eq!(
        unsigned_lake
            .verify_manifest_chain_with_keys(&read_ctx, &[wrong_signer.public_key_bytes()])
            .unwrap_err()
            .code,
        CODE_LAKE_IO
    );

    // Signed lake accepts trusted signer key and rejects untrusted signer key.
    let signer = SigningKeypair::generate().unwrap();
    let signed_lake = LakeStore::open_in_memory(MemoryBlobStore::default(), kek)
        .unwrap()
        .with_signing_key(signer);
    signed_lake
        .append(
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
    signed_lake
        .flush(&ctx, fence, now_ms + 1_000, now_ms)
        .unwrap();
    assert_eq!(signed_lake.verify_manifest_chain(&read_ctx).unwrap(), 1);
    assert_eq!(
        signed_lake
            .verify_manifest_chain_with_keys(&read_ctx, &[wrong_signer.public_key_bytes()])
            .unwrap_err()
            .code,
        CODE_LAKE_IO
    );
}

#[test]
fn lake_erasure_respects_device_holds_across_classes_and_purges_memtable() {
    let kek = AeadKey::generate().unwrap();
    let lake = LakeStore::open_in_memory(MemoryBlobStore::default(), kek).unwrap();
    let org = OrgId::new("org-hold-mem").unwrap();
    let ctx = SingleCtx::new(org);
    let read_ctx = TenantCtx::Single(ctx.clone());
    let fence = FencingToken::new(1);
    let now_ms = 1_700_000_000_000i64;

    let mut r1 = make_record("evt-hm-1", 1, "sess-held", "p1", None, now_ms);
    r1.device_id = "dev-held-99".into();
    let mut r2 = make_record(
        "evt-hm-2",
        2,
        "sess-held",
        "memtable-secret-prompt",
        None,
        now_ms + 500,
    );
    r2.device_id = "dev-held-99".into();

    lake.append(
        &ctx,
        fence,
        &LakeBatch {
            partition: 0,
            bus_offset: 1,
            lane: "evidence".into(),
            records: vec![r1],
            archive_bytes: Vec::new(),
        },
    )
    .unwrap();
    lake.flush(&ctx, fence, now_ms + 100, now_ms + 100).unwrap();

    // Batch 2 stays in memtable with raw archive bytes for the same session.
    lake.append(
        &ctx,
        fence,
        &LakeBatch {
            partition: 0,
            bus_offset: 2,
            lane: "evidence".into(),
            records: vec![r2],
            archive_bytes: b"raw-unflushed-archive-secret".to_vec(),
        },
    )
    .unwrap();

    // Device-scoped Content hold (without session_id) must block erasure!
    lake.place_hold(
        &ctx,
        &LegalHoldRequest {
            hold_id: "hold-dev-content".into(),
            scope: LegalHoldScope {
                tables: vec![RetentionClass::Content],
                day_start: None,
                day_end: None,
                device_ids: vec!["dev-held-99".into()],
                root_session_ids: vec![],
            },
            reason: "incident investigation".into(),
            incident_ref: None,
            created_by: "secops".into(),
            created_at_ms: now_ms,
            expires_at_ms: None,
        },
    )
    .unwrap();
    assert_eq!(
        lake.erase_session(&ctx, "sess-held", "GDPR", now_ms + 1_000)
            .unwrap_err()
            .code,
        CODE_LAKE_HOLD_ACTIVE
    );

    lake.release_hold(&ctx, "hold-dev-content", now_ms + 2_000)
        .unwrap();
    let receipt = lake
        .erase_session(&ctx, "sess-held", "GDPR", now_ms + 3_000)
        .unwrap();
    assert_eq!(receipt.keys_destroyed, 1);

    // Flushing previously queued memtable batch must emit zero archive segments and zero content!
    let post_flush = lake
        .flush(&ctx, fence, now_ms + 4_000, now_ms + 4_000)
        .unwrap();
    assert_eq!(post_flush.archive_segments_written, 0);
    let tl = lake
        .execute_query_ir(
            &read_ctx,
            &LakeQueryIr::Timeline {
                root_session_id: "sess-held".into(),
                include_content: true,
                limit: 10,
            },
        )
        .unwrap();
    assert_eq!(tl.rows.len(), 2);
    for row in &tl.rows {
        assert!(row.content_redacted);
        assert!(!row.columns.contains_key("content.prompt_body"));
    }
}

#[test]
fn lake_compaction_fails_closed_on_missing_blob_and_enforces_daily_put_budget() {
    let kek = AeadKey::generate().unwrap();
    let signer = SigningKeypair::generate().unwrap();
    let lake = LakeStore::open_in_memory(CountingBlobStore::default(), kek.clone())
        .unwrap()
        .with_signing_key(signer);
    let org = OrgId::new("org-compact-fail").unwrap();
    let ctx = SingleCtx::new(org);
    let read_ctx = TenantCtx::Single(ctx.clone());
    let fence = FencingToken::new(1);
    let now_ms = 1_700_000_000_000i64;

    for seq in 1..=2u64 {
        let rec = make_record(&format!("evt-cf-{seq}"), seq, "sess-cf", "p", None, now_ms);
        lake.append(
            &ctx,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: seq,
                lane: "evidence".into(),
                records: vec![rec],
                archive_bytes: Vec::new(),
            },
        )
        .unwrap();
        lake.flush(&ctx, fence, now_ms + 100, now_ms + 100).unwrap();
    }
    let manifest = lake.manifest(&read_ctx).unwrap().unwrap();
    let missing_key = manifest.entries[0].object_key.clone();
    assert!(
        lake.blobs()
            .delete(&ctx, &TenantPath::parse(&ctx, &missing_key).unwrap())
            .unwrap()
    );
    assert_eq!(
        lake.compact_and_retain(&ctx, fence, now_ms + 2_000)
            .unwrap_err()
            .code,
        CODE_LAKE_IO
    );

    // Exhaust daily PUT budget (200 PUTs from 100 segment+manifest flushes) and prove the 101st
    // flush rejects BEFORE issuing any blob store PUT calls.
    let budget_lake = LakeStore::open_in_memory(CountingBlobStore::default(), kek).unwrap();
    let ctx2 = SingleCtx::new(OrgId::new("org-budget-preflight").unwrap());
    for seq in 1..=100u64 {
        let rec = make_record(&format!("evt-b-{seq}"), seq, "sess-b", "p", None, now_ms);
        budget_lake
            .append(
                &ctx2,
                fence,
                &LakeBatch {
                    partition: 0,
                    bus_offset: seq,
                    lane: "evidence".into(),
                    records: vec![rec],
                    archive_bytes: Vec::new(),
                },
            )
            .unwrap();
        budget_lake
            .flush(&ctx2, fence, now_ms + 100, now_ms + 100)
            .unwrap();
    }
    let extra = make_record("evt-b-101", 101, "sess-b", "p", None, now_ms);
    budget_lake
        .append(
            &ctx2,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: 101,
                lane: "evidence".into(),
                records: vec![extra],
                archive_bytes: Vec::new(),
            },
        )
        .unwrap();
    budget_lake.blobs().reset_counters();
    assert_eq!(
        budget_lake
            .flush(&ctx2, fence, now_ms + 100, now_ms + 100)
            .unwrap_err()
            .code,
        CODE_LAKE_IO
    );
    assert_eq!(budget_lake.blobs().put_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn lake_content_field_policy_rejects_unauthorized_scan_aggregate_and_bad_hunt() {
    let kek = AeadKey::generate().unwrap();
    let lake = LakeStore::open_in_memory(MemoryBlobStore::default(), kek).unwrap();
    let org = OrgId::new("org-query-policy").unwrap();
    let ctx = SingleCtx::new(org);
    let read_ctx = TenantCtx::Single(ctx.clone());
    let fence = FencingToken::new(1);
    let now_ms = 1_700_000_000_000i64;
    let rec = make_record("evt-qp-1", 1, "sess-qp", "secret-body", None, now_ms);
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

    let denied_queries = [
        LakeQueryIr::Scan {
            retention_class: RetentionClass::Content,
            category: None,
            predicates: vec![LakePredicate {
                field: "content.prompt_body".into(),
                equals: None,
                contains: Some("secret".into()),
            }],
            projection: vec![],
            include_content: false,
            limit: 10,
        },
        LakeQueryIr::Scan {
            retention_class: RetentionClass::Content,
            category: None,
            predicates: vec![],
            projection: vec!["content.prompt_body".into()],
            include_content: false,
            limit: 10,
        },
        LakeQueryIr::Aggregate {
            retention_class: RetentionClass::Content,
            group_by: vec!["content.prompt_body".into()],
            aggregations: vec![LakeAggSpec {
                alias: "c".into(),
                op: LakeAggOp::Count,
                field: None,
            }],
            predicates: vec![],
        },
        LakeQueryIr::Aggregate {
            retention_class: RetentionClass::Content,
            group_by: vec!["category".into()],
            aggregations: vec![LakeAggSpec {
                alias: "c".into(),
                op: LakeAggOp::Count,
                field: Some("content.prompt_body".into()),
            }],
            predicates: vec![],
        },
        LakeQueryIr::Aggregate {
            retention_class: RetentionClass::Content,
            group_by: vec!["category".into()],
            aggregations: vec![LakeAggSpec {
                alias: "c".into(),
                op: LakeAggOp::Count,
                field: None,
            }],
            predicates: vec![LakePredicate {
                field: "content.prompt_body".into(),
                equals: Some("secret-body".into()),
                contains: None,
            }],
        },
        LakeQueryIr::Hunt {
            sql_select: "SELECT event_id FROM nonexistent_table".into(),
            include_content: false,
            limit: 10,
        },
    ];
    for q in &denied_queries {
        assert_eq!(
            lake.execute_query_ir(&read_ctx, q).unwrap_err().code,
            CODE_LAKE_INVALID_QUERY
        );
    }
}
