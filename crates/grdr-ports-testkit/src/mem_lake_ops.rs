// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use sha2::{Digest, Sha256};

use grdr_ports::{
    ContentKeyState, LakeBatch, LakeManifest, LakeManifestEntry, LakeRecord, LegalHold, OrgId,
    RetentionClass, SessionContentKey,
};

#[derive(Debug, Clone)]
pub(crate) struct MemSegment {
    pub(crate) retention_class: RetentionClass,
    pub(crate) day: String,
    pub(crate) records: Vec<LakeRecord>,
    pub(crate) logically_deleted_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub(crate) struct MemArchiveSegment {
    pub(crate) day: String,
    pub(crate) root_session_ids: BTreeSet<String>,
    pub(crate) reduced: bool,
}

#[derive(Debug, Default)]
pub(crate) struct OrgLakeState {
    pub(crate) fence: u64,
    pub(crate) snapshot_seq: u64,
    pub(crate) manifest_seq: u64,
    pub(crate) tail: Vec<LakeBatch>,
    pub(crate) segments: Vec<MemSegment>,
    pub(crate) archives: Vec<MemArchiveSegment>,
    pub(crate) holds: BTreeMap<String, LegalHold>,
    pub(crate) content_keys: BTreeMap<String, SessionContentKey>,
    pub(crate) manifests: Vec<LakeManifest>,
}

pub(crate) fn flush_due_batches(
    org_id: &OrgId,
    org_state: &mut OrgLakeState,
    due_batches: Vec<LakeBatch>,
    now_ms: i64,
) -> (Option<u64>, usize, usize, usize) {
    let mut committed_through: Option<u64> = None;
    let mut grouped: BTreeMap<(RetentionClass, String), Vec<LakeRecord>> = BTreeMap::new();
    let mut archive_written = 0usize;
    let mut rows_flushed = 0usize;

    for batch in due_batches {
        committed_through =
            Some(committed_through.map_or(batch.bus_offset, |cur| cur.max(batch.bus_offset)));
        let mut session_ids = BTreeSet::new();
        let mut archive_day = day_from_ms(now_ms);
        for rec in batch.records {
            let day = day_from_ms(rec.observed_time_ms);
            archive_day = day.clone();
            session_ids.insert(rec.root_session_id.clone());
            rows_flushed = rows_flushed.saturating_add(1);
            grouped
                .entry((rec.retention_class, day))
                .or_default()
                .push(rec);
        }
        if !batch.archive_bytes.is_empty() {
            archive_written = archive_written.saturating_add(1);
            org_state.archives.push(MemArchiveSegment {
                day: archive_day,
                root_session_ids: session_ids,
                reduced: false,
            });
        }
    }

    let mut segments_written = 0usize;
    let mut manifest_entries = Vec::new();
    for ((class, day), mut records) in grouped {
        records.sort_by(|a, b| {
            (
                &a.device_id,
                &a.root_session_id,
                a.epoch,
                a.monotonic_ns,
                &a.lane,
                a.seq,
            )
                .cmp(&(
                    &b.device_id,
                    &b.root_session_id,
                    b.epoch,
                    b.monotonic_ns,
                    &b.lane,
                    b.seq,
                ))
        });
        org_state.snapshot_seq = org_state.snapshot_seq.saturating_add(1);
        let seg_id = format!("seg-{}-{}", class.as_str(), org_state.snapshot_seq);
        let digest_sha256 = sha256_str(&format!("{seg_id}:{}", records.len()));
        let row_count = u64::try_from(records.len()).unwrap_or(u64::MAX);
        org_state.segments.push(MemSegment {
            retention_class: class,
            day: day.clone(),
            records,
            logically_deleted_at_ms: None,
        });
        segments_written = segments_written.saturating_add(1);
        manifest_entries.push(LakeManifestEntry {
            object_key: format!("class={}/day={day}/{seg_id}.json", class.as_str()),
            retention_class: class,
            day,
            row_count,
            size_bytes: row_count.saturating_mul(128),
            digest_sha256,
            schema_rev: 1,
            data_key_id: format!("dek-{}", org_id.as_str()),
        });
    }

    org_state.manifest_seq = org_state.manifest_seq.saturating_add(1);
    let prev_digest = org_state
        .manifests
        .last()
        .map(|m| m.manifest_digest.clone());
    let manifest_digest = sha256_str(&format!(
        "{}:{}:{}",
        org_id.as_str(),
        org_state.manifest_seq,
        segments_written
    ));
    org_state.manifests.push(LakeManifest {
        organisation_id: org_id.clone(),
        manifest_seq: org_state.manifest_seq,
        prev_manifest_digest: prev_digest,
        manifest_digest,
        object_key: format!("class=manifest/seq-{}.json", org_state.manifest_seq),
        created_at_ms: now_ms,
        entries: manifest_entries,
    });

    (
        committed_through,
        segments_written,
        archive_written,
        rows_flushed,
    )
}

pub(crate) fn partition_due_batches(
    tail: &mut Vec<LakeBatch>,
    due_before_ms: i64,
    now_ms: i64,
) -> (Vec<LakeBatch>, Vec<LakeBatch>) {
    let mut due = Vec::new();
    let mut keep = Vec::new();
    for batch in tail.drain(..) {
        let max_rx = batch
            .records
            .iter()
            .map(|r| r.received_at_ms)
            .max()
            .unwrap_or(now_ms);
        if max_rx <= due_before_ms {
            due.push(batch);
        } else {
            keep.push(batch);
        }
    }
    (due, keep)
}

pub(crate) fn retain_segments(
    segments: &mut [MemSegment],
    active_holds: &[LegalHold],
    now_ms: i64,
) -> (usize, usize, usize) {
    let mut deleted = 0usize;
    let mut held = 0usize;
    let mut observables = 0usize;
    for seg in segments {
        if seg.logically_deleted_at_ms.is_some() {
            continue;
        }
        for rec in &seg.records {
            observables = observables.saturating_add(rec.observables.len());
        }
        let max_obs = seg
            .records
            .iter()
            .map(|r| r.observed_time_ms)
            .max()
            .unwrap_or(now_ms);
        if now_ms.saturating_sub(max_obs) > seg.retention_class.retention_ms() {
            let devices: Vec<String> = seg.records.iter().map(|r| r.device_id.clone()).collect();
            let sessions: Vec<String> = seg
                .records
                .iter()
                .map(|r| r.root_session_id.clone())
                .collect();
            if active_holds
                .iter()
                .any(|h| h.covers(seg.retention_class, &seg.day, &devices, &sessions))
            {
                held = held.saturating_add(1);
            } else {
                seg.logically_deleted_at_ms = Some(now_ms);
                deleted = deleted.saturating_add(1);
            }
        }
    }
    (deleted, held, observables)
}

pub(crate) fn expire_content_keys(
    keys: &mut BTreeMap<String, SessionContentKey>,
    active_holds: &[LegalHold],
    now_ms: i64,
) -> usize {
    let mut destroyed = 0usize;
    for key in keys.values_mut() {
        if matches!(key.state, ContentKeyState::Active) && now_ms >= key.destroy_after_ms {
            let sessions = vec![key.root_session_id.clone()];
            let day = day_from_ms(key.created_at_ms);
            let held = active_holds
                .iter()
                .any(|h| h.covers(RetentionClass::Content, &day, &[], &sessions));
            if !held {
                key.wrapped_key.clear();
                key.state = ContentKeyState::Destroyed {
                    destroyed_at_ms: now_ms,
                    destruction_record_id: format!("retire-{}-{now_ms}", key.root_session_id),
                };
                destroyed = destroyed.saturating_add(1);
            }
        }
    }
    destroyed
}

pub(crate) fn day_from_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1_000);
    let ts = Timestamp::from_second(secs).unwrap_or(Timestamp::UNIX_EPOCH);
    ts.to_string().get(..10).unwrap_or("1970-01-01").to_string()
}

fn sha256_str(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}
