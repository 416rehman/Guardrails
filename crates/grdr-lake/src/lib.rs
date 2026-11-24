// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod crypto;
mod flush;
mod query;
mod query_eval;
mod retention;
mod schema;
mod store;

pub use store::LakeStore;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use grdr_blob::FilesystemBlobStore;
    use grdr_crypto::AeadKey;
    use grdr_ports::{
        EventsPort, FencingToken, LakeBatch, LakeObservable, LakeQueryIr, LakeRecord, OrgId,
        RetentionClass, SingleCtx, TenantCtx,
    };
    use grdr_ports_testkit::MemoryBlobStore;

    use super::*;

    #[test]
    fn lake_store_passes_events_port_contract() {
        let kek = AeadKey::generate().unwrap();
        let store = LakeStore::open_in_memory(MemoryBlobStore::default(), kek).unwrap();
        grdr_ports_testkit::assert_events_port_contract(&store).unwrap();
    }

    #[test]
    fn lake_store_seals_content_with_aead_and_persists_with_filesystem_blobs() {
        let dir = std::env::temp_dir().join(format!("grdr-lake-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let kek = AeadKey::generate().unwrap();
        let blobs = FilesystemBlobStore::open(&dir.join("blobs")).unwrap();
        let lake = LakeStore::open(&dir.join("catalogue.sqlite3"), blobs, kek.clone()).unwrap();

        let org = OrgId::new("org-lake-seal").unwrap();
        let ctx = SingleCtx::new(org);
        let read_ctx = TenantCtx::Single(ctx.clone());
        let fence = FencingToken::new(1);
        let now_ms = 1_700_000_000_000i64;

        let mut content_fields = BTreeMap::new();
        content_fields.insert("prompt_body".into(), "top-secret-prompt".into());

        let rec = LakeRecord {
            event_id: "evt-seal-1".into(),
            device_id: "dev-1".into(),
            epoch: 1,
            lane: "evidence".into(),
            seq: 1,
            retention_class: RetentionClass::Content,
            category: "tool".into(),
            root_session_id: "sess-seal".into(),
            session_id: "sess-seal".into(),
            tool_call_id: None,
            observed_time_ms: now_ms,
            monotonic_ns: 1_000,
            received_at_ms: now_ms,
            schema_rev: 1,
            fields: BTreeMap::new(),
            content_fields,
            observables: vec![LakeObservable {
                observable_type: "host".into(),
                value: "vault.example.test".into(),
            }],
        };

        lake.append(
            &ctx,
            fence,
            &LakeBatch {
                partition: 0,
                bus_offset: 1,
                lane: "evidence".into(),
                records: vec![rec],
                archive_bytes: b"archive-bytes".to_vec(),
            },
        )
        .unwrap();
        let flush_res = lake.flush(&ctx, fence, now_ms + 1_000, now_ms).unwrap();
        assert_eq!(flush_res.rows_flushed, 1);

        // Verify persisted segment blob does NOT contain plaintext secret!
        let manifest = lake.manifest(&read_ctx).unwrap().unwrap();
        let seg_key = &manifest.entries[0].object_key;
        let raw_blob =
            std::fs::read(dir.join("blobs").join("org=org-lake-seal").join(seg_key)).unwrap();
        assert!(!String::from_utf8_lossy(&raw_blob).contains("top-secret-prompt"));

        // Reopen catalogue + blob store and verify content unseals cleanly.
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

        let _ = std::fs::remove_dir_all(&dir);
    }
}
