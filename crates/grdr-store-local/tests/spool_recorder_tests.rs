// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use grdr_store_local::checkpoint::{
    AuditCheckpointPayload, CheckpointError, LaneCheckpointHead, load_and_verify_checkpoint,
    load_and_verify_checkpoint_checked, save_audit_checkpoint,
};
use grdr_store_local::crc32c::crc32c;
use grdr_store_local::recorder::{
    DEFAULT_RECORDER_TTL_SECS, FlightRecorderDb, MAX_DECOMPRESSED_RECORD_BYTES,
    RecorderCaptureLevel, RecorderError,
};
use grdr_store_local::spool::{SegmentedSpool, SpoolPolicy};
use grdr_store_local::spool_io::{
    FLAG_GAP, MAX_SPOOL_RECORD_BYTES, SpoolError, SpoolLane, compute_entry_hash, encode_record,
};
use grdr_store_local::zstd_frame::{
    ZstdFrameError, compress_zstd_frame, decompress_zstd_frame, xxh64,
};

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(prefix: &str) -> Result<Self, Box<dyn Error>> {
        let id = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("grdr-{prefix}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn embedded_spool_policy_respects_limits_toml_512_mb_and_64_mb_reserve() {
    let policy = SpoolPolicy::from_embedded_limits();
    assert_eq!(policy.total_cap_bytes, 512 * 1024 * 1024);
    assert_eq!(policy.decision_reserve_bytes, 64 * 1024 * 1024);
    assert_eq!(policy.segment_bytes, 4 * 1024 * 1024);
}

#[test]
fn segmented_spool_sheds_bulk_before_evidence_and_preserves_decision_reserve() {
    let res = run_segmented_spool_shed();
    assert!(res.is_ok(), "{res:?}");
}

fn run_segmented_spool_shed() -> Result<(), Box<dyn Error>> {
    let dir = ScratchDir::new("spool-shed")?;
    let policy = SpoolPolicy {
        segment_bytes: 512,
        total_cap_bytes: 2400,
        decision_reserve_bytes: 800,
    };
    let mut spool = SegmentedSpool::open(dir.path(), policy)?;

    let bulk_payload = vec![b'B'; 450];
    let evid_payload = vec![b'E'; 450];
    let dec_payload = vec![b'D'; 300];

    let _ = spool.append(SpoolLane::Bulk, &bulk_payload, false)?;
    let _ = spool.append(SpoolLane::Bulk, &bulk_payload, false)?;
    let _ = spool.append(SpoolLane::Evidence, &evid_payload, false)?;
    let outcome = spool.append(SpoolLane::Evidence, &evid_payload, false)?;
    if outcome.emitted_gaps.is_empty() && spool.gap_records().is_empty() {
        return Err("shedding bulk should emit explicit gap record".into());
    }
    for gap in spool.gap_records() {
        if gap.lane != SpoolLane::Bulk || gap.reason != "spool-full" {
            return Err("unexpected gap lane or reason".into());
        }
        if gap.hash_before_gap.is_empty() || gap.hash_after_gap.is_empty() {
            return Err("missing gap chain hashes".into());
        }
    }

    let dec = spool.append(SpoolLane::Decision, &dec_payload, true)?;
    if !dec.fsynced {
        return Err("decision record must be fsynced".into());
    }

    drop(spool);
    let reopened = SegmentedSpool::open(dir.path(), policy)?;
    if reopened.gap_records().is_empty() {
        return Err("reopen must preserve persisted FLAG_GAP records".into());
    }
    let dec_records = reopened.read_lane_records(SpoolLane::Decision)?;
    let first_dec = dec_records.first().ok_or("missing decision record")?;
    if dec_records.len() != 1 || !first_dec.fsynced || first_dec.payload != dec_payload {
        return Err("reopened decision record mismatch".into());
    }
    Ok(())
}

#[test]
fn durable_through_only_prunes_verified_exact_seq_hash_pairs() {
    let res = run_durable_through_prunes();
    assert!(res.is_ok(), "{res:?}");
}

fn run_durable_through_prunes() -> Result<(), Box<dyn Error>> {
    let dir = ScratchDir::new("spool-durable")?;
    let policy = SpoolPolicy {
        segment_bytes: 200,
        total_cap_bytes: 100_000,
        decision_reserve_bytes: 10_000,
    };
    let mut spool = SegmentedSpool::open(dir.path(), policy)?;
    let payload = vec![b's'; 150];
    let first = spool.append(SpoolLane::Spine, &payload, false)?;
    let _second = spool.append(SpoolLane::Spine, &payload, false)?;
    let third = spool.append(SpoolLane::Spine, &payload, false)?;

    let mismatch = spool.acknowledge_durable_through(
        SpoolLane::Spine,
        first.seq,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    if !matches!(mismatch, Err(SpoolError::ChainCorrupt { .. })) {
        return Err("expected ChainCorrupt on mismatched durable_through hash".into());
    }

    let first_hex = grdr_crypto::encode_lower_hex(&first.entry_hash);
    let third_hex = grdr_crypto::encode_lower_hex(&third.entry_hash);
    if !matches!(
        spool.acknowledge_durable_through(SpoolLane::Spine, u64::MAX, &first_hex),
        Err(SpoolError::ChainCorrupt { .. })
    ) {
        return Err("must reject old segment hash paired with u64::MAX seq".into());
    }
    if !matches!(
        spool.acknowledge_durable_through(SpoolLane::Spine, u64::MAX, &third_hex),
        Err(SpoolError::ChainCorrupt { .. })
    ) {
        return Err("must reject tail_hash paired with inflated u64::MAX seq".into());
    }

    let pruned = spool.acknowledge_durable_through(SpoolLane::Spine, first.seq, &first_hex)?;
    if pruned != 1 {
        return Err(format!("expected 1 pruned segment, got {pruned}").into());
    }
    Ok(())
}

#[test]
fn spool_rejects_corruption_splice_lane_mismatch_oversize_and_torn_tail_recovers() {
    let res = run_spool_negative_suite();
    assert!(res.is_ok(), "{res:?}");
}

fn run_spool_negative_suite() -> Result<(), Box<dyn Error>> {
    let policy = SpoolPolicy {
        segment_bytes: 200,
        total_cap_bytes: 100_000,
        decision_reserve_bytes: 10_000,
    };

    // 1. RecordTooLarge guard + atomic SpoolFull without silent deletion.
    let dir1 = ScratchDir::new("spool-neg-cap")?;
    let mut sp1 = SegmentedSpool::open(dir1.path(), policy)?;
    let oversized = vec![0u8; MAX_SPOOL_RECORD_BYTES + 1];
    if !matches!(
        sp1.append(SpoolLane::Bulk, &oversized, false),
        Err(SpoolError::RecordTooLarge { .. })
    ) {
        return Err("expected RecordTooLarge".into());
    }

    let full_dir = ScratchDir::new("spool-neg-full")?;
    let small_pol = SpoolPolicy {
        segment_bytes: 400,
        total_cap_bytes: 1_000,
        decision_reserve_bytes: 700,
    };
    let mut sp_full = SegmentedSpool::open(full_dir.path(), small_pol)?;
    let _ = sp_full.append(SpoolLane::Decision, &[b'D'; 600], true)?;
    let _ = sp_full.append(SpoolLane::Spine, &[b'S'; 150], false)?;
    if !matches!(
        sp_full.append(SpoolLane::Bulk, &[b'B'; 300], false),
        Err(SpoolError::SpoolFull { .. })
    ) {
        return Err("expected SpoolFull when capacity cannot be satisfied".into());
    }
    if sp_full.lane_bytes(SpoolLane::Spine) == 0 {
        return Err("SpoolFull pre-flight must not delete Spine before failing".into());
    }

    // 2. CRC tamper detection.
    let dir_crc = ScratchDir::new("spool-neg-crc")?;
    {
        let mut s = SegmentedSpool::open(dir_crc.path(), policy)?;
        let _ = s.append(SpoolLane::Spine, b"good-record", false)?;
    }
    let seg1 = dir_crc.path().join("spine").join("seg-00000001.seg");
    let mut raw = fs::read(&seg1)?;
    let last_idx = raw.len().saturating_sub(1);
    if let Some(byte) = raw.get_mut(last_idx) {
        *byte ^= 0xFF;
    }
    fs::write(&seg1, raw)?;
    if !matches!(
        SegmentedSpool::open(dir_crc.path(), policy),
        Err(SpoolError::ChainCorrupt { .. })
    ) {
        return Err("expected ChainCorrupt on CRC bit flip".into());
    }

    // 3. Deleted middle segment detection across segments.
    let dir_mid = ScratchDir::new("spool-neg-mid")?;
    {
        let mut s = SegmentedSpool::open(dir_mid.path(), policy)?;
        let chunk = vec![b'm'; 140];
        let _ = s.append(SpoolLane::Spine, &chunk, false)?;
        let _ = s.append(SpoolLane::Spine, &chunk, false)?;
        let _ = s.append(SpoolLane::Spine, &chunk, false)?;
    }
    fs::remove_file(dir_mid.path().join("spine").join("seg-00000002.seg"))?;
    if !matches!(
        SegmentedSpool::open(dir_mid.path(), policy),
        Err(SpoolError::ChainCorrupt { .. })
    ) {
        return Err("deleted middle segment must trigger ChainCorrupt".into());
    }

    // 4. Forged FLAG_GAP with broken prev_hash must fail (no gap chain bypass).
    let dir_gap = ScratchDir::new("spool-neg-gap")?;
    {
        let mut s = SegmentedSpool::open(dir_gap.path(), policy)?;
        let _ = s.append(SpoolLane::Spine, b"rec-1", false)?;
    }
    let gap_seg = dir_gap.path().join("spine").join("seg-00000001.seg");
    let bad_prev = [0xAAu8; 32];
    let bad_payload = br#"{"lane":"spine","first_dropped_seq":1,"last_dropped_seq":1,"dropped_bytes":1,"hash_before_gap":"","hash_after_gap":"","reason":"spool-full"}"#;
    let eh = compute_entry_hash(2, SpoolLane::Spine, FLAG_GAP, &bad_prev, bad_payload);
    let rec_bytes = encode_record(2, SpoolLane::Spine, FLAG_GAP, &bad_prev, &eh, bad_payload)?;
    let mut f = OpenOptions::new().append(true).open(&gap_seg)?;
    f.write_all(&rec_bytes)?;
    if !matches!(
        SegmentedSpool::open(dir_gap.path(), policy),
        Err(SpoolError::ChainCorrupt { .. })
    ) {
        return Err("forged FLAG_GAP prev_hash must fail ChainCorrupt".into());
    }

    // 5. Torn tail truncates cleanly AND empty 0-byte segment drops cleanly.
    let dir_torn = ScratchDir::new("spool-torn")?;
    {
        let mut s = SegmentedSpool::open(dir_torn.path(), policy)?;
        let _ = s.append(SpoolLane::Spine, b"clean-prefix", false)?;
    }
    let torn_seg = dir_torn.path().join("spine").join("seg-00000001.seg");
    let mut f_torn = OpenOptions::new().append(true).open(&torn_seg)?;
    f_torn.write_all(b"GRSPtruncated")?;
    fs::write(dir_torn.path().join("spine").join("seg-00000002.seg"), [])?;
    let reopened = SegmentedSpool::open(dir_torn.path(), policy)?;
    let recs = reopened.read_lane_records(SpoolLane::Spine)?;
    if recs.len() != 1 || recs.first().is_none_or(|r| r.payload != b"clean-prefix") {
        return Err("torn tail recovery must preserve clean prefix".into());
    }
    Ok(())
}

#[test]
fn crc32c_and_zstd_rfc8878_frame_and_sqlite_recorder_ttl_gaps() {
    let res = run_recorder_ttl_gaps();
    assert!(res.is_ok(), "{res:?}");
}

fn run_recorder_ttl_gaps() -> Result<(), Box<dyn Error>> {
    if crc32c(b"123456789") != 0xe306_9283 {
        return Err("crc32c test vector mismatch".into());
    }
    if xxh64(b"", 0) != 0xef46_db37_51d8_e999 {
        return Err("xxh64 empty vector mismatch".into());
    }

    let repeated = vec![b'A'; 512];
    let mut compressed = compress_zstd_frame(&repeated)?;
    if compressed.get(..4) != Some(&[0x28, 0xB5, 0x2F, 0xFD][..]) {
        return Err("missing RFC 8878 magic".into());
    }
    let roundtrip = decompress_zstd_frame(&compressed, 1024)?;
    if roundtrip != repeated {
        return Err("zstd roundtrip mismatch".into());
    }

    // Tampered trailing RFC 8878 checksum must fail fail-closed.
    let cksum_idx = compressed.len().saturating_sub(1);
    if let Some(b) = compressed.get_mut(cksum_idx) {
        *b ^= 0x01;
    }
    if !matches!(
        decompress_zstd_frame(&compressed, 1024),
        Err(ZstdFrameError::InvalidFrame { .. })
    ) {
        return Err("expected InvalidFrame on tampered XXH64 checksum".into());
    }

    // Truncated frame claiming 4 MiB FCS must reject without pre-alloc OOM.
    let fake_fcs = [0x28u8, 0xB5, 0x2F, 0xFD, 0xA0, 0x00, 0x00, 0x40, 0x00];
    if !matches!(
        decompress_zstd_frame(&fake_fcs, MAX_DECOMPRESSED_RECORD_BYTES),
        Err(ZstdFrameError::InvalidFrame { .. })
    ) {
        return Err("expected InvalidFrame on truncated fake-FCS frame".into());
    }
    if !matches!(
        decompress_zstd_frame(&compress_zstd_frame(&repeated)?, 100),
        Err(ZstdFrameError::DecompressedLimitExceeded { .. })
    ) {
        return Err("expected decompressed limit exceeded".into());
    }

    let dir = ScratchDir::new("recorder-db")?;
    let mut db = FlightRecorderDb::open(dir.path().join("recorder.db"))?;
    let oversized = vec![b'X'; MAX_DECOMPRESSED_RECORD_BYTES + 1];
    if !matches!(
        db.append_event(2_000_000_000, "decision", "receipt", "s1", &oversized),
        Err(RecorderError::InvalidArgument { .. })
    ) {
        return Err("append_event must reject >4 MiB payload".into());
    }

    let now = 2_000_000_000i64;
    let old_ts = now - DEFAULT_RECORDER_TTL_SECS - 120;
    let _ = db.append_event(
        old_ts,
        "decision",
        "receipt",
        "sess-old",
        b"old-payload-aaaaa",
    )?;
    let _ = db.append_event(
        now - 60,
        "decision",
        "receipt",
        "sess-new",
        b"fresh-payload",
    )?;

    if !matches!(
        db.purge_expired(now, 60),
        Err(RecorderError::InvalidArgument { .. })
    ) {
        return Err("purge_expired must enforce 24h minimum TTL".into());
    }

    let gap = db
        .purge_expired(now, DEFAULT_RECORDER_TTL_SECS)?
        .ok_or("expected gap row")?;
    if gap.dropped_count != 1 || gap.reason != "recorder-expired" {
        return Err("unexpected recorder expiration gap".into());
    }

    let fresh = db.query_events(0, now + 100, Some("sess-new"), 10)?;
    let first_fresh = fresh.first().ok_or("missing fresh record")?;
    if fresh.len() != 1 || first_fresh.payload != b"fresh-payload" {
        return Err("unexpected fresh query results".into());
    }
    let meta_only = db.query_events_at_level(
        0,
        now + 100,
        Some("sess-new"),
        10,
        RecorderCaptureLevel::MetadataOnly,
    )?;
    if meta_only.first().is_none_or(|r| !r.payload.is_empty()) {
        return Err("MetadataOnly capture must withhold payload".into());
    }
    if db.list_gaps()?.len() != 1 {
        return Err("expected 1 gap row".into());
    }

    // Cumulative 32 MiB query cap stops safely instead of allocating unbounded memory.
    let big_dir = ScratchDir::new("recorder-cap")?;
    let mut big_db = FlightRecorderDb::open(big_dir.path().join("recorder.db"))?;
    let four_mib = vec![b'Z'; MAX_DECOMPRESSED_RECORD_BYTES];
    for i in 0..10 {
        let _ = big_db.append_event(now + i, "evidence", "blob", "sess-big", &four_mib)?;
    }
    let capped = big_db.query_events(0, now + 100, Some("sess-big"), 100)?;
    if capped.len() > 8 {
        return Err("query_events must cap cumulative decompressed bytes at 32 MiB".into());
    }

    // Multi-batch cache cap convergence across large incompressible payloads + 24h recorder-short gap.
    let tight_dir = ScratchDir::new("recorder-tight-cap")?;
    let mut tight_db =
        FlightRecorderDb::open_with_cache_cap(tight_dir.path().join("recorder.db"), 4096)?;
    let mut chunk = vec![0u8; 1024];
    for i in 0..80 {
        for (idx, b) in chunk.iter_mut().enumerate() {
            *b = ((idx.wrapping_mul(17).wrapping_add(i as usize)) % 251) as u8;
        }
        let _ = tight_db.append_event(now + i, "evidence", "blob", "sess-tight", &chunk)?;
    }
    let remaining = tight_db.query_events(0, now + 1000, None, 1000)?;
    if remaining.len() > 10 {
        return Err(format!(
            "enforce_cache_cap must converge within cap, left {} rows",
            remaining.len()
        )
        .into());
    }
    let tight_gaps = tight_db.list_gaps()?;
    if !tight_gaps.iter().any(|g| g.reason == "recorder-short") {
        return Err("evicting <24h rows under cap overflow must record recorder-short gap".into());
    }
    Ok(())
}

#[test]
fn signed_audit_checkpoint_persists_and_detects_tampering_and_rollback() {
    let res = run_signed_checkpoint();
    assert!(res.is_ok(), "{res:?}");
}

fn run_signed_checkpoint() -> Result<(), Box<dyn Error>> {
    let dir = ScratchDir::new("checkpoint")?;
    let path = dir.path().join("audit.checkpoint");
    let key = grdr_crypto::SigningKeypair::generate()?;
    let mut lanes = BTreeMap::new();
    lanes.insert(
        SpoolLane::Decision,
        LaneCheckpointHead {
            head_seq: 42,
            head_hash_hex: "abcd".into(),
            durable_through_seq: 40,
        },
    );
    let payload = AuditCheckpointPayload {
        schema_version: 1,
        updated_at_unix_s: 1_900_000_000,
        gap_count: 0,
        lanes,
        device_id: "dev-hash-1".into(),
        epoch: 3,
        recorder_head_seq: 12,
    };
    save_audit_checkpoint(&path, &payload, &key)?;
    let loaded =
        load_and_verify_checkpoint(&path, &key.public_key_b64())?.ok_or("expected checkpoint")?;
    if loaded.payload != payload {
        return Err("checkpoint payload mismatch".into());
    }

    if !matches!(
        load_and_verify_checkpoint_checked(&path, &key.public_key_b64(), "dev-hash-1", 4),
        Err(CheckpointError::Malformed { .. })
    ) {
        return Err("anti-rollback check must reject stale checkpoint epoch".into());
    }

    let wrong_key = grdr_crypto::SigningKeypair::generate()?;
    if load_and_verify_checkpoint(&path, &wrong_key.public_key_b64()).is_ok() {
        return Err("expected signature rejection for wrong key".into());
    }

    // Tamper timestamp without changing key -> signature must reject.
    let txt = fs::read_to_string(&path)?;
    let tampered = txt.replacen("1900000000", "1900000001", 1);
    fs::write(&path, tampered)?;
    if !matches!(
        load_and_verify_checkpoint(&path, &key.public_key_b64()),
        Err(CheckpointError::InvalidSignature)
    ) {
        return Err("same-key checkpoint tamper must trigger InvalidSignature".into());
    }
    Ok(())
}
