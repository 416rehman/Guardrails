// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_ports::{
    CODE_LAKE_INVALID_QUERY, CODE_LAKE_STALE_FENCE, EventsPort, FencingToken, LakeAggOp,
    LakeAggSpec, LakeBatch, LakeObservable, LakePredicate, LakeQueryIr, LakeRecord,
    LegalHoldRequest, LegalHoldScope, OrgId, RetentionClass, SingleCtx, TenantCtx,
};

const MS_PER_DAY: i64 = 86_400_000;

fn sample_record(
    event_id: &str,
    device_id: &str,
    root_session_id: &str,
    seq: u64,
    retention_class: RetentionClass,
    observed_time_ms: i64,
    with_content: bool,
) -> LakeRecord {
    let mut fields = BTreeMap::new();
    fields.insert("action_class".into(), "exec".into());
    fields.insert("target".into(), "cargo test".into());
    fields.insert("cost".into(), "10".into());

    let mut content_fields = BTreeMap::new();
    if with_content {
        content_fields.insert("prompt_body".into(), format!("secret-prompt-{event_id}"));
    }

    LakeRecord {
        event_id: event_id.into(),
        device_id: device_id.into(),
        epoch: 1,
        lane: if retention_class == RetentionClass::Decision {
            "decision".into()
        } else {
            "spine".into()
        },
        seq,
        retention_class,
        category: "tool".into(),
        root_session_id: root_session_id.into(),
        session_id: root_session_id.into(),
        tool_call_id: Some(format!("tc-{seq}")),
        observed_time_ms,
        monotonic_ns: seq.saturating_mul(1_000),
        received_at_ms: observed_time_ms,
        schema_rev: 1,
        fields,
        content_fields,
        observables: vec![LakeObservable {
            observable_type: "host".into(),
            value: "api.example.test".into(),
        }],
    }
}

pub fn assert_events_port_contract(lake: &impl EventsPort) -> Result<(), String> {
    let org_a = OrgId::new("org-lake-a").map_err(|e| e.to_string())?;
    let org_b = OrgId::new("org-lake-b").map_err(|e| e.to_string())?;
    let ctx_a = SingleCtx::new(org_a.clone());
    let ctx_b = SingleCtx::new(org_b.clone());
    let read_a = TenantCtx::Single(ctx_a.clone());
    let read_b = TenantCtx::Single(ctx_b.clone());
    let read_both = TenantCtx::set("snap-lake", vec![org_a, org_b]).map_err(|e| e.to_string())?;

    let now_ms: i64 = 1_700_000_000_000;
    let f2 = FencingToken::new(2);
    let f1 = FencingToken::new(1);

    let rec_a1 = sample_record(
        "evt-a1",
        "dev-1",
        "sess-root-1",
        1,
        RetentionClass::Activity,
        now_ms,
        true,
    );
    let rec_a2 = sample_record(
        "evt-a2",
        "dev-1",
        "sess-root-1",
        2,
        RetentionClass::Content,
        now_ms,
        true,
    );
    let batch_a = LakeBatch {
        partition: 0,
        bus_offset: 10,
        lane: "spine".into(),
        records: vec![rec_a1, rec_a2],
        archive_bytes: b"raw-archive-batch-a".to_vec(),
    };
    let appended = lake
        .append(&ctx_a, f2, &batch_a)
        .map_err(|e| e.to_string())?;
    if appended != 2 {
        return Err(format!("expected 2 appended records, got {appended}"));
    }

    let Err(stale) = lake.append(&ctx_a, f1, &batch_a) else {
        return Err("expected stale fence rejection on append".into());
    };
    if stale.code != CODE_LAKE_STALE_FENCE {
        return Err(format!(
            "expected {}, got {}",
            CODE_LAKE_STALE_FENCE, stale.code
        ));
    }

    let tail_timeline = lake
        .execute_query_ir(
            &read_a,
            &LakeQueryIr::Timeline {
                root_session_id: "sess-root-1".into(),
                include_content: true,
                limit: 10,
            },
        )
        .map_err(|e| e.to_string())?;
    if tail_timeline.rows.len() != 2 || tail_timeline.tail_rows_merged < 2 {
        return Err("expected 2 tail rows in Timeline before flush".into());
    }

    let flushed = lake
        .flush(&ctx_a, f2, now_ms.saturating_add(1_000), now_ms)
        .map_err(|e| e.to_string())?;
    if flushed.rows_flushed != 2 || flushed.segments_written < 1 {
        return Err("expected flush to persist segments".into());
    }
    let manifest = lake
        .manifest(&read_a)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "expected manifest after flush".to_string())?;
    if manifest.entries.is_empty() {
        return Err("expected non-empty manifest entries".into());
    }

    let batch_b = LakeBatch {
        partition: 0,
        bus_offset: 11,
        lane: "decision".into(),
        records: vec![sample_record(
            "evt-b1",
            "dev-2",
            "sess-root-b",
            1,
            RetentionClass::Decision,
            now_ms,
            false,
        )],
        archive_bytes: b"raw-archive-batch-b".to_vec(),
    };
    lake.append(&ctx_b, f2, &batch_b)
        .map_err(|e| e.to_string())?;
    if !lake
        .execute_query_ir(
            &read_b,
            &LakeQueryIr::Timeline {
                root_session_id: "sess-root-1".into(),
                include_content: false,
                limit: 10,
            },
        )
        .map_err(|e| e.to_string())?
        .rows
        .is_empty()
    {
        return Err("org B must not read org A timeline".into());
    }
    if lake
        .execute_query_ir(
            &read_both,
            &LakeQueryIr::Export {
                retention_class: None,
                cursor: None,
                include_content: false,
                limit: 10,
            },
        )
        .map_err(|e| e.to_string())?
        .rows
        .len()
        != 3
    {
        return Err("SetCtx export should observe all 3 records across org A and B".into());
    }

    let scan = lake
        .execute_query_ir(
            &read_a,
            &LakeQueryIr::Scan {
                retention_class: RetentionClass::Activity,
                category: Some("tool".into()),
                predicates: vec![LakePredicate {
                    field: "device_id".into(),
                    equals: Some("dev-1".into()),
                    contains: None,
                }],
                projection: vec!["event_id".into(), "action_class".into()],
                include_content: false,
                limit: 10,
            },
        )
        .map_err(|e| e.to_string())?;
    if scan.rows.len() != 1 {
        return Err("expected 1 row in Activity Scan".into());
    }

    let agg = lake
        .execute_query_ir(
            &read_a,
            &LakeQueryIr::Aggregate {
                retention_class: RetentionClass::Activity,
                group_by: vec!["action_class".into()],
                aggregations: vec![LakeAggSpec {
                    alias: "cnt".into(),
                    op: LakeAggOp::Count,
                    field: None,
                }],
                predicates: vec![],
            },
        )
        .map_err(|e| e.to_string())?;
    if agg.rows.len() != 1
        || agg
            .rows
            .first()
            .and_then(|r| r.columns.get("cnt"))
            .map(String::as_str)
            != Some("1")
    {
        return Err("expected Aggregate count == 1".into());
    }

    let lookup = lake
        .execute_query_ir(
            &read_a,
            &LakeQueryIr::Lookup {
                observable_type: Some("host".into()),
                value: "api.example.test".into(),
                limit: 10,
            },
        )
        .map_err(|e| e.to_string())?;
    if lookup.rows.len() != 2 {
        return Err("expected Lookup to match both org A events".into());
    }

    let hunt = lake
        .execute_query_ir(
            &read_a,
            &LakeQueryIr::Hunt {
                sql_select: "SELECT event_id FROM activity WHERE target = 'cargo test' LIMIT 5"
                    .into(),
                include_content: false,
                limit: 5,
            },
        )
        .map_err(|e| e.to_string())?;
    if hunt.rows.len() != 1 {
        return Err("expected Hunt query to match 1 activity row".into());
    }

    let Err(bad_hunt) = lake.execute_query_ir(
        &read_a,
        &LakeQueryIr::Hunt {
            sql_select: "DROP TABLE activity".into(),
            include_content: false,
            limit: 5,
        },
    ) else {
        return Err("expected invalid Hunt SQL to fail".into());
    };
    if bad_hunt.code != CODE_LAKE_INVALID_QUERY {
        return Err(format!(
            "expected {}, got {}",
            CODE_LAKE_INVALID_QUERY, bad_hunt.code
        ));
    }

    let hold = lake
        .place_hold(
            &ctx_a,
            &LegalHoldRequest {
                hold_id: "hold-1".into(),
                scope: LegalHoldScope {
                    tables: vec![RetentionClass::Content],
                    day_start: None,
                    day_end: None,
                    device_ids: vec![],
                    root_session_ids: vec!["sess-root-1".into()],
                },
                reason: "Incident investigation".into(),
                incident_ref: Some("inc-42".into()),
                created_by: "secops".into(),
                created_at_ms: now_ms,
                expires_at_ms: None,
            },
        )
        .map_err(|e| e.to_string())?;
    if hold.hold_id != "hold-1" {
        return Err("unexpected hold_id".into());
    }

    let future_40d = now_ms.saturating_add(40i64.saturating_mul(MS_PER_DAY));
    let held_compact = lake
        .compact_and_retain(&ctx_a, f2, future_40d)
        .map_err(|e| e.to_string())?;
    if held_compact.segments_held < 1 {
        return Err("expected legal hold to protect Content segment from retention".into());
    }

    let receipt = lake
        .erase_session(&ctx_a, "sess-root-1", "GDPR request", future_40d)
        .map_err(|e| e.to_string())?;
    if receipt.keys_destroyed != 1 || receipt.held_segments_deferred < 1 {
        return Err("expected key destruction and held archive deferral on erase_session".into());
    }

    let post_erase = lake
        .execute_query_ir(
            &read_a,
            &LakeQueryIr::Timeline {
                root_session_id: "sess-root-1".into(),
                include_content: true,
                limit: 10,
            },
        )
        .map_err(|e| e.to_string())?;
    if post_erase.rows.len() != 2 || !post_erase.rows.iter().all(|r| r.content_redacted) {
        return Err("expected metadata preserved with content_redacted=true after erase".into());
    }

    lake.release_hold(&ctx_a, "hold-1", future_40d)
        .map_err(|e| e.to_string())?;
    let released_compact = lake
        .compact_and_retain(&ctx_a, f2, future_40d)
        .map_err(|e| e.to_string())?;
    if released_compact.segments_logically_deleted < 1 {
        return Err("expected released hold to allow Content segment retention".into());
    }

    Ok(())
}
