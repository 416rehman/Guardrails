// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde_json::Value;

use grdr_blob::FilesystemBlobStore;
use grdr_lake::LakeStore;
use grdr_model::CodedError;
use grdr_ports::{
    EventsPort, FencingToken, LakeBatch, LakeObservable, LakeRecord, RetentionClass, SingleCtx,
};

pub(crate) fn append_event_to_lake(
    lake: &LakeStore<FilesystemBlobStore>,
    org_ctx: &SingleCtx,
    fence: FencingToken,
    bus_offset: u64,
    device_id: &str,
    payload_bytes: &[u8],
    now_ms: i64,
) -> Result<u64, CodedError> {
    let record = build_record_from_payload(bus_offset, device_id, payload_bytes, now_ms);
    let batch = LakeBatch {
        partition: 0,
        bus_offset,
        lane: record.lane.clone(),
        records: vec![record],
        archive_bytes: payload_bytes.to_vec(),
    };
    lake.append(org_ctx, fence, &batch)
}

fn build_record_from_payload(
    bus_offset: u64,
    device_id: &str,
    payload_bytes: &[u8],
    now_ms: i64,
) -> LakeRecord {
    let parsed: Option<Value> = serde_json::from_slice(payload_bytes).ok();
    let event_id = parsed
        .as_ref()
        .and_then(|v| v.get("receipt_id").and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_else(|| format!("evt-bus-{bus_offset}"));
    let session_id = parsed
        .as_ref()
        .and_then(|v| v.get("session_id").and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_else(|| format!("sess-{device_id}"));
    let target = parsed
        .as_ref()
        .and_then(|v| v.get("target").and_then(Value::as_str))
        .map(str::to_string);

    let mut fields = BTreeMap::new();
    fields.insert("device_id".into(), device_id.to_string());
    if let Some(ref tgt) = target {
        fields.insert("target".into(), tgt.clone());
    }
    if let Some(verdict) = parsed
        .as_ref()
        .and_then(|v| v.get("verdict").and_then(Value::as_str))
    {
        fields.insert("verdict".into(), verdict.to_string());
    }

    let mut observables = Vec::new();
    if let Some(tgt) = target {
        observables.push(LakeObservable {
            observable_type: "target".into(),
            value: tgt,
        });
    }

    LakeRecord {
        event_id,
        device_id: device_id.to_string(),
        epoch: 1,
        lane: "decision".into(),
        seq: bus_offset.saturating_add(1),
        retention_class: RetentionClass::Decision,
        category: "decision".into(),
        root_session_id: session_id.clone(),
        session_id,
        tool_call_id: None,
        observed_time_ms: now_ms,
        monotonic_ns: bus_offset.saturating_mul(1_000),
        received_at_ms: now_ms,
        schema_rev: 1,
        fields,
        content_fields: BTreeMap::new(),
        observables,
    }
}
